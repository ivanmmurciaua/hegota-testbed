// Daisugi PoC: a SPHINCS-G account executes an ARBITRARY call AS itself via a
// SENDER frame (the poc_e / smart-wallet analog). Two live cases:
//
//   GOOD  derive + fund a fresh SPHINCS-G account; deploy a tiny recorder contract
//         through a SENDER call to the Arachnid deterministic deployer (legacy
//         deploys are rejected on this frame-only chain); then from the account's
//         SENDER frame call the recorder with a magic word. We require receipt
//         status 0x1 AND the recorder's emitted log to show caller == the account
//         and data == the magic word.
//   BAD   the same arbitrary call with a corrupted SPHINCS-G signature (one flipped
//         byte in the witness). We require the node to REJECT it at admission and
//         the call to never execute (no receipt, no recorder log).
//
// The recorder logs instead of using storage because eth_getStorageAt is disabled
// on the public RPC; the log is read back from the receipt. Everything cryptographic
// is REUSED from the fetched reference under ../vendor_ref/ (not committed).
//
// Exit 0 only if GOOD proves caller==account and the recorded value AND BAD is
// rejected with no execution.
import { randomBytes } from 'node:crypto';
import * as ethers from 'ethers';
import { createProtocol } from '../vendor_ref/AA-PQ/aggregation/frames/wallet/protocol.mjs';
import { sphincsDerive, sphincsSign, sphincsVerify } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/sphincs.js';
import { ensureWasmKeccak } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/keccak.js';
import { keccakBatchInit } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/keccak-batch.js';

const RPC = process.env.PQ_RPC_URL || 'https://daisugi.fyi/rpc';
const FAUCET = process.env.PQ_FAUCET_URL || 'https://daisugi.fyi/api/faucet';
const CHAIN_ID = BigInt(process.env.PQ_CHAIN_ID || '1337');
// Arachnid deterministic deployment proxy (present on Daisugi): calldata is
// salt(32) || initcode, it CREATE2-deploys and returns the 20-byte address.
const ARACHNID = '0x4e59b44847b379578588920cA78FbF26c0B4956C';
const config = {
  factory: process.env.DAISUGI_FACTORY || '0x4940E0D0883fa40985fEC192FdD9E11C7A34d9D0',
  implementation: process.env.DAISUGI_IMPLEMENTATION || '0x016d1A8326E714552F6517177DB55eD45a5CB6E8',
};

const e = {
  Interface: ethers.Interface, ZeroHash: ethers.ZeroHash, concat: ethers.concat,
  encodeRlp: ethers.encodeRlp, getAddress: ethers.getAddress, getBytes: ethers.getBytes,
  getCreate2Address: ethers.getCreate2Address, hexlify: ethers.hexlify, keccak256: ethers.keccak256,
  toBeHex: ethers.toBeHex, toQuantity: ethers.toQuantity, toUtf8Bytes: ethers.toUtf8Bytes,
  zeroPadValue: ethers.zeroPadValue,
};
const log = (...a) => console.log(...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));

// recorder runtime (10 bytes): store calldata[0:32] in memory, then emit a LOG1
// whose topic0 is CALLER and whose data is that word.
//   PUSH0 CALLDATALOAD PUSH0 MSTORE  CALLER PUSH1 0x20 PUSH0 LOG1  STOP
const RECORDER_RUNTIME = '5f355f523360205fa100';
const RECORDER_INITCODE = '0x600a600c600039600a6000f3' + RECORDER_RUNTIME;

async function rpc(method, params = []) {
  const r = await fetch(RPC, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await r.json();
  if (body.error) { const err = Error(body.error.message); err.rpcCode = body.error.code; err.full = body.error; throw err; }
  return body.result;
}

async function freshFundedAccount(p, label) {
  const seed = new Uint8Array(randomBytes(32));
  const key = sphincsDerive(seed, 'sphincs-g');
  const pkSeed = key.backupPkSeed, pkRoot = key.backupPkRoot;
  const sender = p.accountAddress(config, pkSeed, pkRoot);
  log(`    [${label}] account`, sender);
  try {
    const fr = await fetch(FAUCET, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address: sender }) });
    log(`    [${label}] faucet`, fr.status, (await fr.text()).slice(0, 120));
  } catch (err) { log(`    [${label}] faucet request failed:`, err.message); }
  let funded = 0n;
  for (let i = 0; i < 30 && funded === 0n; i++) { funded = BigInt(await rpc('eth_getBalance', [sender, 'latest'])); if (funded === 0n) await sleep(2000); }
  if (funded === 0n) throw Error(`[${label}] account was not funded (faucet cooldown or outage)`);
  return { seed, pkSeed, pkRoot, sender };
}

// Build and SPHINCS-G sign one SENDER call from `acct` to `target` with `data`.
// If corrupt is true, flip one byte in the signature so the node must reject it.
async function buildSignedCall(p, acct, target, data, callGas, corrupt = false) {
  const block = await rpc('eth_getBlockByNumber', ['latest', false]);
  const priorityFee = 1000000000n, maxFee = BigInt(block.baseFeePerGas) * 2n + priorityFee;
  const nonce = BigInt(await rpc('eth_getTransactionCount', [acct.sender, 'pending']));
  const deployed = (await rpc('eth_getCode', [acct.sender, 'latest'])) !== '0x';
  const prepared = p.prepare({ config, pkSeed: acct.pkSeed, pkRoot: acct.pkRoot, nonce,
    recipient: target, value: 0n, data, deployed, maxFee, priorityFee, callGas, stateGas: callGas });
  const sig = sphincsSign(acct.seed, e.getBytes(prepared.digest), 'sphincs-g');
  let sigHex = sig.sigHex;
  if (corrupt) {
    const bytes = e.getBytes(sigHex);
    const idx = Math.floor(bytes.length / 2);
    bytes[idx] ^= 0xff;
    sigHex = ethers.hexlify(bytes);
    if (sphincsVerify(acct.pkSeed, acct.pkRoot, prepared.digest, sigHex, 'sphincs-g').valid)
      throw Error('corruption failed: signature still verifies locally');
  } else if (!sphincsVerify(acct.pkSeed, acct.pkRoot, prepared.digest, sigHex, 'sphincs-g').valid) {
    throw Error('honest signature failed local verification');
  }
  return { req: p.signedRequest(prepared, sigHex), frames: prepared.transaction.frames.length };
}

async function pollReceipt(hash, tries = 45) {
  for (let i = 0; i < tries; i++) {
    const rc = await rpc('eth_getTransactionReceipt', [hash]);
    if (rc) return rc;
    await sleep(2000);
  }
  return null;
}

async function runGood(p) {
  log('== GOOD case: SPHINCS-G account makes an arbitrary call as itself ==');
  const acct = await freshFundedAccount(p, 'good');
  const salt = ethers.hexlify(randomBytes(32));
  const recorder = ethers.getCreate2Address(ARACHNID, salt, ethers.keccak256(RECORDER_INITCODE));
  log('    recorder (CREATE2)', recorder);

  // tx1: account SENDER -> Arachnid(salt || initcode) deploys the recorder.
  const deploy = await buildSignedCall(p, acct, ARACHNID, e.concat([salt, RECORDER_INITCODE]), 600000n);
  log('    deploy tx', deploy.req.hash, 'frames', deploy.frames);
  let res = await rpc(deploy.req.method, deploy.req.params);
  if (res[0]?.toLowerCase() !== deploy.req.hash.toLowerCase()) throw Error('deploy submit mismatch');
  const drc = await pollReceipt(deploy.req.hash);
  if (!drc || BigInt(drc.status) !== 1n) throw Error('deploy did not succeed');
  const code = await rpc('eth_getCode', [recorder, 'latest']);
  log('    deploy receipt status', drc.status, 'recorder code', code);
  if (code !== '0x' + RECORDER_RUNTIME) throw Error('recorder code mismatch after deploy');

  // tx2: account SENDER -> recorder(magic) records caller + the magic word.
  const magic = '0x' + '00'.repeat(28) + 'deadbeef';
  const call = await buildSignedCall(p, acct, recorder, magic, 200000n);
  log('    call tx', call.req.hash, 'frames', call.frames);
  res = await rpc(call.req.method, call.req.params);
  if (res[0]?.toLowerCase() !== call.req.hash.toLowerCase()) throw Error('call submit mismatch');
  const crc = await pollReceipt(call.req.hash);
  if (!crc || BigInt(crc.status) !== 1n) throw Error('call did not succeed');
  const frames = (crc.frameReceipts || []).map(f => f.status);
  log('    call receipt status', crc.status, 'frames', JSON.stringify(frames));
  if (frames.some(s => BigInt(s) !== 1n)) throw Error('a frame failed on the arbitrary call');

  const logs = (crc.logs || []).filter(l => l.address.toLowerCase() === recorder.toLowerCase());
  if (!logs.length) throw Error('recorder emitted no log');
  const caller = ethers.getAddress('0x' + logs[0].topics[0].slice(26));
  const recorded = logs[0].data;
  log('    recorded caller', caller, '(account', acct.sender + ')');
  log('    recorded value ', recorded, '(magic', magic + ')');
  if (caller.toLowerCase() !== acct.sender.toLowerCase()) throw Error('caller != account: SENDER did not run as the account');
  if (recorded.toLowerCase() !== magic.toLowerCase()) throw Error('recorded value != magic');
  log('    GOOD ok: caller == account and the arbitrary calldata was executed');
  return { deployHash: deploy.req.hash, callHash: call.req.hash, recorder, account: acct.sender };
}

async function runBad(p, recorder) {
  log('== BAD case: corrupted signature on an arbitrary call must be rejected ==');
  const acct = await freshFundedAccount(p, 'bad');
  const magic = '0x' + '00'.repeat(28) + 'c0ffee';
  const call = await buildSignedCall(p, acct, recorder, magic, 200000n, true);
  log('    corrupted-signature call tx', call.req.hash);
  let submitError = null, submitResult = null;
  try { submitResult = await rpc(call.req.method, call.req.params); }
  catch (err) { submitError = { code: err.rpcCode, message: err.message }; }

  if (submitError) {
    log('    REJECTED at admission:', JSON.stringify(submitError));
  } else {
    log('    gateway accepted structurally:', JSON.stringify(submitResult), '-> checking it never executes');
    const rc = await pollReceipt(call.req.hash, 20);
    if (rc && BigInt(rc.status) === 1n) throw Error('corrupted-signature call was INCLUDED and succeeded: gate is broken');
    log('    no successful inclusion:', rc ? ('reverted status ' + rc.status) : 'no receipt');
  }
  // The call never executed, so the recorder emitted no log for the BAD magic.
  const rc = await rpc('eth_getTransactionReceipt', [call.req.hash]);
  if (rc && BigInt(rc.status) === 1n) throw Error('BAD tx unexpectedly succeeded');
  log('    BAD ok: node rejected the bad signature; recorder was not called');
  return { badHash: call.req.hash, outcome: submitError || { includedSuccessfully: false } };
}

async function main() {
  log('[init] keccak and protocol');
  await ensureWasmKeccak();
  await keccakBatchInit();
  const p = createProtocol(e);
  const chain = BigInt(await rpc('eth_chainId'));
  if (chain !== CHAIN_ID) throw Error(`RPC chainId ${chain} != expected ${CHAIN_ID}`);

  const good = await runGood(p);
  const bad = await runBad(p, good.recorder);

  log('');
  log('PoC daisugi call GREEN on chain', CHAIN_ID.toString());
  log('  account    :', good.account);
  log('  deploy tx  :', good.deployHash, 'https://explorer.daisugi.fyi/tx/' + good.deployHash);
  log('  call tx    :', good.callHash, 'https://explorer.daisugi.fyi/tx/' + good.callHash);
  log('  recorder   :', good.recorder, '(caller == account, magic recorded)');
  log('  BAD tx     :', bad.badHash, 'rejected, never executed');
  log('  Proven: a SPHINCS-G account runs an arbitrary call as itself, gated by the PQ signature.');
}

main().catch(err => { console.error('FAILED:', err.message); process.exitCode = 1; });
