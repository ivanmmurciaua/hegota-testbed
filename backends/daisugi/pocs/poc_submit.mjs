// Daisugi PoC: SPHINCS-G-sign a type-0x06 frame transaction and submit it to the
// live Daisugi RPC via eth_sendProofWrapper, then poll for an on-chain receipt.
//
// The SPHINCS-G signer, the v2 digest, the Gen2 RLP codec and the proof-wrapper
// assembly are imported from the reference under ../vendor_ref/ (set up by setup.sh).
// This file is our glue only: config from env, key generation, faucet, submit, poll.
//
// Network config comes from the backend env (run.sh sources backends/daisugi/env):
//   PQ_RPC_URL, PQ_FAUCET_URL, PQ_CHAIN_ID, DAISUGI_FACTORY, DAISUGI_IMPLEMENTATION.
// Exit 0 on receipt status 0x1; non-zero (with the exact error) otherwise.
import { randomBytes } from 'node:crypto';
import * as ethers from 'ethers';
import { createProtocol } from '../vendor_ref/AA-PQ/aggregation/frames/wallet/protocol.mjs';
import { sphincsDerive, sphincsSign, sphincsVerify } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/sphincs.js';
import { ensureWasmKeccak } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/keccak.js';
import { keccakBatchInit } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/keccak-batch.js';

const RPC = process.env.PQ_RPC_URL || 'https://daisugi.fyi/rpc';
const FAUCET = process.env.PQ_FAUCET_URL || 'https://daisugi.fyi/api/faucet';
const CHAIN_ID = BigInt(process.env.PQ_CHAIN_ID || '1337');
const config = {
  factory: process.env.DAISUGI_FACTORY || '0x4940E0D0883fa40985fEC192FdD9E11C7A34d9D0',
  implementation: process.env.DAISUGI_IMPLEMENTATION || '0x016d1A8326E714552F6517177DB55eD45a5CB6E8',
};

// The protocol/account-profile modules expect an injected ethers-primitives object.
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

async function main() {
  log('[1] init keccak and protocol');
  await ensureWasmKeccak();
  await keccakBatchInit();
  const p = createProtocol(e);
  const chain = BigInt(await rpc('eth_chainId'));
  if (chain !== CHAIN_ID) throw Error(`RPC chainId ${chain} != expected ${CHAIN_ID}`);

  log('[2] fresh SPHINCS-G keypair');
  const seed = new Uint8Array(randomBytes(32));
  const key = sphincsDerive(seed, 'sphincs-g');
  const pkSeed = key.backupPkSeed, pkRoot = key.backupPkRoot;
  const sender = p.accountAddress(config, pkSeed, pkRoot);
  log('    account (CREATE2):', sender);

  log('[3] fund via faucet');
  try {
    const fr = await fetch(FAUCET, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address: sender }) });
    log('    faucet', fr.status, (await fr.text()).slice(0, 160));
  } catch (err) { log('    faucet request failed:', err.message); }
  let funded = 0n;
  for (let i = 0; i < 30 && funded === 0n; i++) { funded = BigInt(await rpc('eth_getBalance', [sender, 'latest'])); if (funded === 0n) await sleep(2000); }
  if (funded === 0n) throw Error('account was not funded (faucet cooldown or outage)');
  log('    balance', funded.toString());

  log('[4] build tx (first send: deploy + DEP_VERIFY + VERIFY + SENDER self)');
  const block = await rpc('eth_getBlockByNumber', ['latest', false]);
  const priorityFee = 1000000000n, maxFee = BigInt(block.baseFeePerGas) * 2n + priorityFee;
  const nonce = BigInt(await rpc('eth_getTransactionCount', [sender, 'pending']));
  const deployed = (await rpc('eth_getCode', [sender, 'latest'])) !== '0x';
  const prepared = p.prepare({ config, pkSeed, pkRoot, nonce, recipient: sender, value: 0n, data: '0x',
    deployed, maxFee, priorityFee, callGas: 250000n, stateGas: 250000n });
  log('    frames', prepared.transaction.frames.length, 'digest', prepared.digest);

  log('[5] SPHINCS-G sign the v2 digest');
  const t0 = Date.now();
  const sig = sphincsSign(seed, e.getBytes(prepared.digest), 'sphincs-g');
  log('    signed in', Date.now() - t0, 'ms; sig bytes', e.getBytes(sig.sigHex).length);
  if (!sphincsVerify(sig.backupPkSeed, sig.backupPkRoot, prepared.digest, sig.sigHex, 'sphincs-g').valid)
    throw Error('local signature verification failed');

  log('[6] assemble proof wrapper and submit');
  const req = p.signedRequest(prepared, sig.sigHex);
  log('    tx hash', req.hash, 'method', req.method, 'wrapper bytes', e.getBytes(req.wrapper).length);
  let res;
  try { res = await rpc(req.method, req.params); }
  catch (err) { log('    SUBMIT ERROR code', err.rpcCode, 'msg', err.message, 'full', JSON.stringify(err.full)); throw err; }
  if (!Array.isArray(res) || res[0]?.toLowerCase() !== req.hash.toLowerCase()) throw Error('unexpected submit result: ' + JSON.stringify(res));
  log('    accepted into pool:', JSON.stringify(res));

  log('[7] poll receipt');
  for (let i = 0; i < 45; i++) {
    const rc = await rpc('eth_getTransactionReceipt', [req.hash]);
    if (rc) {
      const frames = (rc.frameReceipts || []).map(f => f.status);
      log('    RECEIPT status', rc.status, 'block', rc.blockNumber, 'gasUsed', rc.gasUsed, 'frames', JSON.stringify(frames));
      if (BigInt(rc.status) !== 1n) throw Error('tx failed: receipt status ' + rc.status);
      if (frames.some(s => BigInt(s) !== 1n)) throw Error('a frame failed: ' + JSON.stringify(frames));
      log('');
      log('PoC daisugi GREEN: SPHINCS-G-signed type-0x06 accepted on chain', CHAIN_ID.toString());
      log('  tx:', req.hash);
      log('  explorer: https://explorer.daisugi.fyi/tx/' + req.hash);
      return;
    }
    await sleep(2000);
  }
  throw Error('no receipt after polling; tx hash ' + req.hash);
}

main().catch(err => { console.error('FAILED:', err.message); process.exitCode = 1; });
