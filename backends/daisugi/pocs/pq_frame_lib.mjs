// Shared glue for the Gen1 in-frame PQ paymaster PoCs (Daisugi, chainId 1337).
//
// All cryptography and the Gen1 codec are REUSED at runtime from the fetched
// reference under ../vendor_ref/ (not committed): the SPHINCS-G signer and the
// native-frame signing-hash/RLP codec. This module is our glue only: RPC, faucet,
// receipts, deterministic deploys through the Arachnid proxy, and an EOA frame-tx
// builder for the one faucet-funded deployer. Contract runtimes are authored by our
// own generator in ./pq_account_gen.mjs.
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import * as ethers from 'ethers';
import {
  signingHash, encodeFrame, quantity, accountAddress, accountRuntime, buildTransfer, signedFrame, FACTORY_ABI,
} from '../vendor_ref/AA-PQ/native-wallet-original/src/native-frame/protocol.js';
import { sphincsDerive, sphincsSign, sphincsVerify } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/sphincs.js';
import { ensureWasmKeccak } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/keccak.js';
import { keccakBatchInit } from '../vendor_ref/AA-PQ/native-wallet-original/src/crypto/keccak-batch.js';

export { ethers, signingHash, encodeFrame, quantity, accountAddress, accountRuntime, buildTransfer, signedFrame, FACTORY_ABI };
export { sphincsDerive, sphincsSign, sphincsVerify };

export const RPC = process.env.PQ_RPC_URL || 'https://daisugi.fyi/rpc';
export const FAUCET = process.env.PQ_FAUCET_URL || 'https://daisugi.fyi/api/faucet';
export const CHAIN_ID = BigInt(process.env.PQ_CHAIN_ID || '1337');
// Arachnid deterministic deployment proxy: calldata = salt(32) || initCode, CREATE2.
export const ARACHNID = '0x4e59b44847b379578588920cA78FbF26c0B4956C';

export const log = (...a) => console.log(...a);
export const sleep = ms => new Promise(r => setTimeout(r, ms));
const q = quantity;

export async function rpc(method, params = []) {
  const r = await fetch(RPC, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await r.json();
  if (body.error) { const err = Error(body.error.message); err.rpcCode = body.error.code; err.full = body.error; throw err; }
  return body.result;
}

export async function initCrypto() { await ensureWasmKeccak(); await keccakBatchInit(); }

export async function assertChain() {
  const chain = BigInt(await rpc('eth_chainId'));
  if (chain !== CHAIN_ID) throw Error(`RPC chainId ${chain} != expected ${CHAIN_ID}`);
}

export async function hasCode(address) {
  return (await rpc('eth_getCode', [address, 'latest'])) !== '0x';
}

export async function faucetFund(address, label, minWei = 1n) {
  try {
    const fr = await fetch(FAUCET, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address }) });
    log(`    [${label}] faucet`, fr.status, (await fr.text()).slice(0, 90));
  } catch (err) { log(`    [${label}] faucet request failed:`, err.message); }
  let funded = 0n;
  for (let i = 0; i < 30 && funded < minWei; i++) {
    funded = BigInt(await rpc('eth_getBalance', [address, 'latest']));
    if (funded < minWei) await sleep(2000);
  }
  if (funded < minWei) throw Error(`[${label}] not funded (faucet cooldown or outage), have ${funded}`);
  return funded;
}

export async function pollReceipt(hash, tries = 60) {
  for (let i = 0; i < tries; i++) {
    const rc = await rpc('eth_getTransactionReceipt', [hash]);
    if (rc) return rc;
    await sleep(2000);
  }
  return null;
}

export async function feeParams() {
  const block = await rpc('eth_getBlockByNumber', ['latest', false]);
  const priorityFee = 1000000000n;
  const maxFee = BigInt(block.baseFeePerGas) * 2n + priorityFee;
  return { priorityFee, maxFee };
}

// Compile our CREATE2 clone factory (Yul) to creation bytecode via solc.
export function compileYul(source, objectName) {
  const dir = mkdtempSync(join(tmpdir(), 'daisugi-yul-'));
  const file = join(dir, `${objectName}.yul`);
  writeFileSync(file, source);
  const out = execFileSync('solc', ['--strict-assembly', '--bin', file], { encoding: 'utf8' });
  const m = out.match(/Binary representation:\s*([0-9a-fA-F]+)/);
  if (!m) throw Error('solc produced no binary:\n' + out);
  return '0x' + m[1];
}

// A SECP256K1 witness over the canonical signing hash: v(1) || r(32) || s(32).
// This is the format the node's built-in default EOA verifier expects.
export function k1Witness(wallet, digest) {
  const s = wallet.signingKey.sign(digest);
  return ethers.concat([ethers.toBeHex(s.yParity, 1), s.r, s.s]);
}

// An operator witness for OUR paymaster contract's ecrecover: r(32) || s(32) || v(1)
// with v == 27 or 28, the layout its authored runtime parses.
export function operatorWitness(wallet, digest) {
  const s = wallet.signingKey.sign(digest);
  return ethers.concat([s.r, s.s, ethers.toBeHex(27 + s.yParity, 1)]);
}

// A fresh SPHINCS-G key: seed plus the 16-byte public-key halves padded to words.
export function freshSphincsKey() {
  const seed = new Uint8Array(randomBytes(32));
  const key = sphincsDerive(seed, 'sphincs-g');
  // backupPkSeed/backupPkRoot are already 32-byte words (16 meaningful bytes,
  // left-aligned, right-padded with 16 zero bytes), exactly the clone layout wants.
  return { seed, pkSeed: key.backupPkSeed, pkRoot: key.backupPkRoot };
}

// Deploy `creationBytecode` deterministically through Arachnid from the faucet-funded
// deployer EOA, as a Gen1 frame tx: a self VERIFY (flags 3) then a SENDER frame that
// calls the proxy with salt || initCode. Returns the created contract address.
export async function deployViaArachnid(deployer, creationBytecode, salt, label) {
  const address = ethers.getCreate2Address(ARACHNID, salt, ethers.keccak256(creationBytecode));
  if (await hasCode(address)) { log(`    [${label}] already deployed`, address); return address; }
  const { priorityFee, maxFee } = await feeParams();
  const nonce = BigInt(await rpc('eth_getTransactionCount', [deployer.address, 'pending']));
  const data = ethers.concat([salt, creationBytecode]);
  const frames = [
    [q(1), q(3), deployer.address, [q(100000), '0x'], '0x', '0x'],          // VERIFY self, approve both
    [q(2), '0x', ARACHNID, [q(1500000), q(1500000)], '0x', data],           // SENDER: proxy deploys
  ];
  const payload = [q(CHAIN_ID), q(nonce), deployer.address, frames,
    [[q(1), deployer.address, '0x', '0x']], [q(priorityFee), q(maxFee), '0x'], []];
  const digest = signingHash(payload);
  payload[4][0][3] = k1Witness(deployer, digest);
  const raw = encodeFrame(payload);
  const hash = await rpc('eth_sendRawTransaction', [raw]);
  log(`    [${label}] deploy tx`, hash);
  const rc = await pollReceipt(hash);
  if (!rc || BigInt(rc.status) !== 1n) throw Error(`[${label}] deploy failed, receipt ${JSON.stringify(rc && rc.status)}`);
  if (!(await hasCode(address))) throw Error(`[${label}] no code at ${address} after deploy`);
  log(`    [${label}] deployed`, address, 'via', hash);
  return address;
}

// Call an arbitrary method on a contract from the deployer EOA via a SENDER frame
// (used to drive factory.createAccount). Returns the receipt.
export async function deployerCall(deployer, target, data, label, callGas = 600000n) {
  const { priorityFee, maxFee } = await feeParams();
  const nonce = BigInt(await rpc('eth_getTransactionCount', [deployer.address, 'pending']));
  const frames = [
    [q(1), q(3), deployer.address, [q(100000), '0x'], '0x', '0x'],
    [q(2), '0x', target, [q(callGas), q(callGas)], '0x', data],
  ];
  const payload = [q(CHAIN_ID), q(nonce), deployer.address, frames,
    [[q(1), deployer.address, '0x', '0x']], [q(priorityFee), q(maxFee), '0x'], []];
  const digest = signingHash(payload);
  payload[4][0][3] = k1Witness(deployer, digest);
  const raw = encodeFrame(payload);
  const hash = await rpc('eth_sendRawTransaction', [raw]);
  log(`    [${label}] tx`, hash);
  const rc = await pollReceipt(hash);
  if (!rc || BigInt(rc.status) !== 1n) throw Error(`[${label}] call failed, receipt ${JSON.stringify(rc && rc.status)}`);
  return { hash, receipt: rc };
}
