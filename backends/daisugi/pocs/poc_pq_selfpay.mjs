// Daisugi STEP A: a Gen1 in-frame SPHINCS account self-pays a transfer.
//
// De-risks the PQ paymaster goal by proving that our OWN authored account runtime
// (the EIP-1167 clone that verifies a SPHINCS-G signature in-frame via opcode 0xb5
// SIGDATACOPY + a STATICCALL to the live SPHINCS-G verifier) works end to end on the
// live network with APPROVE scope 3 (self-pay). Every rail role here is a contract:
// the account is a clone of our own impl, created by our own CREATE2 factory; only
// the deployer is a faucet-funded EOA.
//
//   GOOD  deploy our impl + factory via the Arachnid proxy; derive + fund a fresh
//         SPHINCS account; submit ONE self-pay frame tx (deploy frame -> VERIFY
//         flags 3 -> SENDER moves value). Assert: tx mined, every frame succeeded,
//         the account's clone code is present, the exact value moved to the recipient.
//   BAD   the same self-pay tx with a corrupted SPHINCS signature (one flipped byte).
//         The in-frame VERIFY must reject it so nothing moves.
//
// Exit 0 only if GOOD moved the exact value AND BAD was rejected with recipient 0.
// Reuses the reference SPHINCS signer and native-frame codec at runtime; the account
// and factory bytecode are produced by our own generator in pq_account_gen.mjs.
import * as ethers from 'ethers';
import {
  rpc, log, initCrypto, assertChain, feeParams, faucetFund, pollReceipt, hasCode,
  deployViaArachnid, compileYul, freshSphincsKey, sphincsSign, sphincsVerify,
  accountAddress, buildTransfer, signedFrame, signingHash, encodeFrame, CHAIN_ID,
} from './pq_frame_lib.mjs';
import { buildAccountRuntime, deployInitCode, factoryYul, SPHINCS_VERIFIER } from './pq_account_gen.mjs';

const TRANSFER_VALUE = 123n; // wei moved by the SENDER frame
// Deterministic deploy salts for our impl and factory (public, not secret).
const IMPL_SALT_A = ethers.id('r1do.pq.selfpay.impl.v1');
const FACT_SALT_A = ethers.id('r1do.pq.selfpay.factory.v1');

// Deploy (or reuse) the scope-3 impl and its CREATE2 clone factory. Verifies the
// impl's on-chain runtime is exactly what our generator emits before trusting it.
async function deployAccountContracts(deployer) {
  const implRuntime = buildAccountRuntime(3, SPHINCS_VERIFIER);
  const impl = await deployViaArachnid(deployer, deployInitCode(implRuntime), IMPL_SALT_A, 'impl3');
  const onchain = await rpc('eth_getCode', [impl, 'latest']);
  if (onchain.toLowerCase() !== implRuntime.toLowerCase())
    throw Error('deployed impl runtime does not match our generated runtime');
  log('    impl runtime verified on-chain (byte-exact with our generator)');
  const factoryBytecode = compileYul(factoryYul(impl), 'AccountFactory');
  const factory = await deployViaArachnid(deployer, factoryBytecode, FACT_SALT_A, 'factory3');
  return { impl, factory, config: { implementation: impl, factory } };
}

// Build + SPHINCS-sign a self-pay transfer (optionally corrupting the signature).
async function buildSelfPay(config, key, account, recipient, corrupt = false) {
  const { priorityFee, maxFee } = await feeParams();
  const nonce = BigInt(await rpc('eth_getTransactionCount', [account, 'pending']));
  const deployed = await hasCode(account);
  const payload = buildTransfer({
    config, pkSeed: key.pkSeed, pkRoot: key.pkRoot, sender: account, recipient,
    nonce, value: TRANSFER_VALUE, deployed, maxFee, priorityFee, callGas: 200000n,
  });
  const digest = signingHash(payload);
  const sig = sphincsSign(key.seed, ethers.getBytes(digest), 'sphincs-g');
  let sigHex = sig.sigHex;
  if (corrupt) {
    const b = ethers.getBytes(sigHex); b[Math.floor(b.length / 2)] ^= 0xff; sigHex = ethers.hexlify(b);
    if (sphincsVerify(key.pkSeed, key.pkRoot, digest, sigHex, 'sphincs-g').valid)
      throw Error('corruption failed: signature still verifies locally');
  } else if (!sphincsVerify(key.pkSeed, key.pkRoot, digest, sigHex, 'sphincs-g').valid) {
    throw Error('honest signature failed local verification');
  }
  const raw = encodeFrame(signedFrame(payload, sigHex));
  const hash = ethers.keccak256(raw);
  return { raw, hash, frames: payload[3].length };
}

async function runGood(deployer, config) {
  log('== GOOD: SPHINCS account self-pays a transfer (in-frame VERIFY, scope 3) ==');
  const key = freshSphincsKey();
  const account = accountAddress(config, key.pkSeed, key.pkRoot);
  const recipient = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));
  log('    account', account);
  log('    recipient', recipient);
  await faucetFund(account, 'account', ethers.parseEther('0.01')); // account self-pays gas + value
  const rBefore = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  if (rBefore !== 0n) throw Error('recipient not empty before transfer');

  const tx = await buildSelfPay(config, key, account, recipient);
  log('    tx', tx.hash, 'frames', tx.frames);
  const res = await rpc('eth_sendRawTransaction', [tx.raw]);
  if (res.toLowerCase() !== tx.hash.toLowerCase()) throw Error('submit hash mismatch: ' + JSON.stringify(res));
  const rc = await pollReceipt(tx.hash);
  if (!rc) throw Error('GOOD tx produced no receipt');
  const frameStatuses = (rc.frameReceipts || []).map(f => f.status);
  const frameGas = (rc.frameReceipts || []).map(f => f.gasUsed);
  log('    receipt status', rc.status, 'block', rc.blockNumber, 'frames', JSON.stringify(frameStatuses));
  log('    per-frame gasUsed', JSON.stringify(frameGas), '(frame[1] is the SPHINCS VERIFY)');
  if (BigInt(rc.status) !== 1n || frameStatuses.some(s => BigInt(s) !== 1n)) throw Error('GOOD tx did not fully succeed');

  if (!(await hasCode(account))) throw Error('account clone not deployed');
  const rAfter = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  if (rAfter - rBefore !== TRANSFER_VALUE) throw Error(`recipient delta ${rAfter - rBefore} != ${TRANSFER_VALUE}`);
  log('    GOOD ok: in-frame SPHINCS VERIFY ran, clone deployed, value moved exactly');
  return { hash: tx.hash, account, recipient, verifyGas: frameGas[1] };
}

async function runBad(deployer, config) {
  log('== BAD: corrupted SPHINCS signature must make the in-frame VERIFY reject ==');
  const key = freshSphincsKey();
  const account = accountAddress(config, key.pkSeed, key.pkRoot);
  const recipient = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));
  log('    account', account);
  await faucetFund(account, 'account-bad', ethers.parseEther('0.01'));
  const rBefore = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));

  const tx = await buildSelfPay(config, key, account, recipient, true);
  log('    corrupted tx', tx.hash);
  let submitError = null;
  try { await rpc('eth_sendRawTransaction', [tx.raw]); }
  catch (err) { submitError = { code: err.rpcCode, message: err.message }; }
  if (submitError) log('    REJECTED at admission:', JSON.stringify(submitError));
  else {
    log('    accepted structurally -> checking it never succeeds');
    const rc = await pollReceipt(tx.hash, 20);
    if (rc && BigInt(rc.status) === 1n) throw Error('corrupted-signature tx succeeded: in-frame gate is broken');
    log('    not successfully included:', rc ? 'reverted ' + rc.status : 'no receipt');
  }
  const rAfter = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  if (rAfter !== rBefore) throw Error('recipient received value from a corrupted-signature tx');
  log('    BAD ok: nothing moved');
  return { hash: tx.hash, outcome: submitError || { includedSuccessfully: false } };
}

async function main() {
  log('[init] keccak + protocol');
  await initCrypto();
  await assertChain();
  log('[deployer] fresh faucet-funded EOA');
  const deployer = ethers.Wallet.createRandom();
  log('    deployer', deployer.address);
  await faucetFund(deployer.address, 'deployer', ethers.parseEther('0.05'));
  log('[contracts] deploy our impl + factory via Arachnid');
  const { impl, factory, config } = await deployAccountContracts(deployer);

  const good = await runGood(deployer, config);
  const bad = await runBad(deployer, config);

  log('');
  log('PoC daisugi PQ self-pay GREEN on chain', CHAIN_ID.toString());
  log('  impl     :', impl);
  log('  factory  :', factory);
  log('  GOOD tx  :', good.hash, 'https://explorer.daisugi.fyi/tx/' + good.hash);
  log('  account  :', good.account, '(in-frame SPHINCS VERIFY ran, self-pay)');
  log('  verifyGas:', good.verifyGas, '(gas used by the SPHINCS VERIFY frame)');
  log('  BAD tx   :', bad.hash, 'rejected, recipient still 0');
  log('  Proven: a contract PQ account verifies its SPHINCS-G signature in-frame and self-pays a transfer on Daisugi (Gen1).');
}

main().catch(err => { console.error('FAILED:', err.message); process.exitCode = 1; });
