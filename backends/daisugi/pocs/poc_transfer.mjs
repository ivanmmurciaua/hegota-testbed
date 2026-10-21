// Daisugi PoC: REAL transactions that verify SPHINCS-G signatures AND move ETH.
//
// Two live cases against PQ_RPC_URL (Daisugi, chainId 1337):
//   GOOD  a fresh SPHINCS-G account sends value > 0 to a fresh recipient in a
//         SENDER frame; we require receipt status 0x1 AND the recipient balance
//         to go from 0 to exactly the sent value.
//   BAD   the same transfer with a corrupted SPHINCS-G signature (one flipped
//         byte in the witness). We require the node to REJECT it (admission error
//         or no inclusion) and the recipient to receive nothing. This proves the
//         node actually verifies the post-quantum signature, not just the client.
//
// Everything cryptographic is REUSED from the fetched third-party reference under
// ../vendor_ref/ (not committed): the SPHINCS-G signer, the v2 digest, the Gen2
// RLP codec and the proof-wrapper assembly. This file is our glue only.
//
// Exit 0 only if GOOD moved the exact value AND BAD was rejected with recipient 0.
import { randomBytes } from 'node:crypto';
import * as ethers from 'ethers';
import { createProtocol } from '../vendor_ref/AA-PQ/aggregation/frames/wallet/protocol.mjs';
import { sphincsDerive, sphincsSign, sphincsVerify } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/sphincs.js';
import { ensureWasmKeccak } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/keccak.js';
import { keccakBatchInit } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/keccak-batch.js';

const RPC = process.env.PQ_RPC_URL || 'https://daisugi.fyi/rpc';
const FAUCET = process.env.PQ_FAUCET_URL || 'https://daisugi.fyi/api/faucet';
const CHAIN_ID = BigInt(process.env.PQ_CHAIN_ID || '1337');
const TRANSFER_VALUE = 1000000000000000n; // 0.001 ETH
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

async function rpc(method, params = []) {
  const r = await fetch(RPC, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await r.json();
  if (body.error) { const err = Error(body.error.message); err.rpcCode = body.error.code; err.full = body.error; throw err; }
  return body.result;
}

// Fresh SPHINCS-G account, faucet-funded. Returns { seed, pkSeed, pkRoot, sender }.
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
  log(`    [${label}] balance`, funded.toString());
  return { seed, pkSeed, pkRoot, sender };
}

// Build + SPHINCS-G sign a value transfer from `acct` to `recipient`.
// Returns { prepared, sigHex } ready for signedRequest.
async function buildSignedTransfer(p, acct, recipient) {
  const block = await rpc('eth_getBlockByNumber', ['latest', false]);
  const priorityFee = 1000000000n, maxFee = BigInt(block.baseFeePerGas) * 2n + priorityFee;
  const nonce = BigInt(await rpc('eth_getTransactionCount', [acct.sender, 'pending']));
  const deployed = (await rpc('eth_getCode', [acct.sender, 'latest'])) !== '0x';
  const prepared = p.prepare({ config, pkSeed: acct.pkSeed, pkRoot: acct.pkRoot, nonce,
    recipient, value: TRANSFER_VALUE, data: '0x', deployed, maxFee, priorityFee, callGas: 250000n, stateGas: 250000n });
  const sig = sphincsSign(acct.seed, e.getBytes(prepared.digest), 'sphincs-g');
  return { prepared, sigHex: sig.sigHex, pkSeed: sig.backupPkSeed, pkRoot: sig.backupPkRoot };
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
  log('== GOOD case: SPHINCS-G transfer moves ETH ==');
  const acct = await freshFundedAccount(p, 'good');
  const recipient = ethers.getAddress(ethers.hexlify(randomBytes(20)));
  log('    recipient (fresh)', recipient);
  const before = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  log('    recipient balance before', before.toString());
  if (before !== 0n) throw Error('recipient was not empty before the transfer');

  const { prepared, sigHex } = await buildSignedTransfer(p, acct, recipient);
  if (!sphincsVerify(acct.pkSeed, acct.pkRoot, prepared.digest, sigHex, 'sphincs-g').valid)
    throw Error('local signature verification failed for the honest signature');
  const req = p.signedRequest(prepared, sigHex);
  log('    tx', req.hash, 'value', TRANSFER_VALUE.toString(), 'wei');
  const res = await rpc(req.method, req.params);
  if (!Array.isArray(res) || res[0]?.toLowerCase() !== req.hash.toLowerCase()) throw Error('unexpected submit result: ' + JSON.stringify(res));

  const rc = await pollReceipt(req.hash);
  if (!rc) throw Error('GOOD tx produced no receipt');
  const frames = (rc.frameReceipts || []).map(f => f.status);
  log('    receipt status', rc.status, 'block', rc.blockNumber, 'frames', JSON.stringify(frames));
  if (BigInt(rc.status) !== 1n || frames.some(s => BigInt(s) !== 1n)) throw Error('GOOD tx did not fully succeed');

  const after = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  const delta = after - before;
  log('    recipient balance after', after.toString(), '(delta', delta.toString() + ')');
  if (delta !== TRANSFER_VALUE) throw Error(`recipient delta ${delta} != sent ${TRANSFER_VALUE}`);
  log('    GOOD ok: signature verified, value moved exactly');
  return { ok: true, hash: req.hash, delta };
}

async function runBad(p) {
  log('== BAD case: corrupted SPHINCS-G signature must be rejected ==');
  const acct = await freshFundedAccount(p, 'bad');
  const recipient = ethers.getAddress(ethers.hexlify(randomBytes(20)));
  log('    recipient (fresh)', recipient);
  const before = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  if (before !== 0n) throw Error('recipient was not empty before the transfer');

  const { prepared, sigHex } = await buildSignedTransfer(p, acct, recipient);
  // Flip one byte in the middle of the 6176-byte signature; length stays valid so
  // the structural checks pass and the NODE is the one that must reject it.
  const sigBytes = e.getBytes(sigHex);
  const idx = Math.floor(sigBytes.length / 2);
  sigBytes[idx] ^= 0xff;
  const badSig = ethers.hexlify(sigBytes);
  log('    corrupted sig byte at index', idx);
  if (sphincsVerify(acct.pkSeed, acct.pkRoot, prepared.digest, badSig, 'sphincs-g').valid)
    throw Error('corrupted signature still verifies locally; corruption failed');
  log('    local verify of corrupted sig: invalid (as expected)');

  const req = p.signedRequest(prepared, badSig);
  log('    tx', req.hash);
  let submitError = null, submitResult = null;
  try { submitResult = await rpc(req.method, req.params); }
  catch (err) { submitError = { code: err.rpcCode, message: err.message, full: err.full }; }

  if (submitError) {
    log('    REJECTED at admission:', JSON.stringify(submitError));
  } else {
    log('    gateway accepted structurally:', JSON.stringify(submitResult), '-> checking it is never included');
    const rc = await pollReceipt(req.hash, 20);
    if (rc && BigInt(rc.status) === 1n) throw Error('BAD tx with corrupted signature was INCLUDED and succeeded: gate is broken');
    log('    no successful inclusion:', rc ? ('reverted status ' + rc.status) : 'no receipt');
  }

  const after = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  log('    recipient balance after', after.toString());
  if (after !== 0n) throw Error('recipient received value from a corrupted-signature tx: gate is broken');
  log('    BAD ok: node rejected the bad signature and recipient got nothing');
  return { ok: true, outcome: submitError || { includedSuccessfully: false }, hash: req.hash };
}

async function main() {
  log('[init] keccak and protocol');
  await ensureWasmKeccak();
  await keccakBatchInit();
  const p = createProtocol(e);
  const chain = BigInt(await rpc('eth_chainId'));
  if (chain !== CHAIN_ID) throw Error(`RPC chainId ${chain} != expected ${CHAIN_ID}`);

  const good = await runGood(p);
  const bad = await runBad(p);

  log('');
  log('PoC daisugi transfer GREEN on chain', CHAIN_ID.toString());
  log('  GOOD tx:', good.hash, 'recipient delta 0 ->', good.delta.toString(), 'wei');
  log('  GOOD explorer: https://explorer.daisugi.fyi/tx/' + good.hash);
  log('  BAD  tx:', bad.hash, 'rejected, recipient still 0');
  log('  Proven: the node verifies SPHINCS-G signatures and moves ETH only for valid ones.');
}

main().catch(err => { console.error('FAILED:', err.message); process.exitCode = 1; });
