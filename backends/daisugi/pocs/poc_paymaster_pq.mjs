// Daisugi STEP B: a post-quantum account sponsored by a paymaster, BOTH contracts.
//
// This replaces the k1-EOA paymaster checkpoint (poc_paymaster.mjs) with a version
// where every rail role is a contract and no EOA appears in a rail role (only the
// faucet-funded deployer is an EOA):
//   - the account is an EIP-1167 clone of our execution-only SPHINCS impl (APPROVE
//     scope 2), created by our own CREATE2 factory; it verifies its SPHINCS-G
//     signature in-frame and approves EXECUTION only;
//   - the paymaster is our own contract; in its VERIFY frame it ecrecovers a
//     secp256k1 operator signature from its ARBITRARY witness, requires the baked-in
//     operator, and approves PAYMENT; it pays the gas.
//
// Sponsored tx frames: [ VERIFY account flags 2 -> SPHINCS verify + APPROVE exec ],
//   [ VERIFY paymaster flags 1 -> ecrecover(operator) + APPROVE payment ],
//   [ SENDER moves value ]. Two ARBITRARY witnesses: idx 0 = SPHINCS (account verify),
// idx 1 = operator secp256k1 (paymaster verify).
//
//   GOOD  assert tx mined, receipt.payer == paymaster (NOT the account), the account's
//         balance delta == only the moved value (zero gas), the recipient received it.
//   BAD   a corrupted operator signature must make the paymaster VERIFY revert so the
//         tx never mines and nothing moves.
//
// The execution-only account drops the reference self-pay "sole witness" assertion
// (TXPARAM 0x0b == 1), which is incompatible with a second (paymaster) witness; that
// is the only intentional difference from the scope-3 self-pay account. Reuses the
// reference SPHINCS signer and native-frame codec at runtime; account/paymaster/factory
// bytecode is produced by our own generator in pq_account_gen.mjs.
//
// Exit 0 only if GOOD is sponsored correctly AND BAD is rejected with nothing moved.
import * as ethers from 'ethers';
import {
  rpc, log, initCrypto, assertChain, feeParams, faucetFund, pollReceipt, hasCode,
  deployViaArachnid, deployerCall, compileYul, freshSphincsKey, sphincsSign, sphincsVerify,
  operatorWitness, accountAddress, signingHash, encodeFrame, quantity as q, FACTORY_ABI, CHAIN_ID,
} from './pq_frame_lib.mjs';
import {
  buildAccountRuntime, buildPaymasterRuntime, deployInitCode, factoryYul, SPHINCS_VERIFIER,
} from './pq_account_gen.mjs';

const TRANSFER_VALUE = 123n;
const ACCT_VERIFY_GAS = 415000n;   // SPHINCS VERIFY frame budget (Step A measured ~384k used)
const PAY_VERIFY_GAS = 70000n;     // paymaster VERIFY frame budget (ecrecover is cheap)
// 415000 + 70000 = 485000, under the 500000 public-mempool validation-prefix budget.
const IMPL_SALT_B = ethers.id('r1do.pq.sponsored.impl.v1');
const FACT_SALT_B = ethers.id('r1do.pq.sponsored.factory.v1');
const PAYMASTER_SALT = ethers.id('r1do.pq.paymaster.v1');

async function deployContracts(deployer, operator) {
  // Execution-only account impl (scope 2, not sole-witness) + its CREATE2 factory.
  const implRuntime = buildAccountRuntime(2, SPHINCS_VERIFIER, { soleWitness: false });
  const impl = await deployViaArachnid(deployer, deployInitCode(implRuntime), IMPL_SALT_B, 'impl2');
  if ((await rpc('eth_getCode', [impl, 'latest'])).toLowerCase() !== implRuntime.toLowerCase())
    throw Error('deployed exec-only impl != our generated runtime');
  log('    exec-only impl verified on-chain (byte-exact with our generator)');
  const factory = await deployViaArachnid(deployer, compileYul(factoryYul(impl), 'AccountFactory'), FACT_SALT_B, 'factory2');

  // Paymaster contract with the operator baked in.
  const payRuntime = buildPaymasterRuntime(operator.address);
  const paymaster = await deployViaArachnid(deployer, deployInitCode(payRuntime), PAYMASTER_SALT, 'paymaster');
  if ((await rpc('eth_getCode', [paymaster, 'latest'])).toLowerCase() !== payRuntime.toLowerCase())
    throw Error('deployed paymaster != our generated runtime');
  log('    paymaster verified on-chain (byte-exact with our generator), operator', operator.address);
  return { impl, factory, paymaster, config: { implementation: impl, factory } };
}

// Build + sign a sponsored transfer. Returns { raw, hash }.
function buildSponsored(account, paymaster, recipient, nonce, key, operator, fees, corruptOperator = false) {
  const frames = [
    [q(1), q(2), account,   [q(ACCT_VERIFY_GAS), '0x'], '0x', '0x'],          // VERIFY account: approve EXECUTION
    [q(1), q(1), paymaster, [q(PAY_VERIFY_GAS), '0x'], '0x', '0x'],           // VERIFY paymaster: approve PAYMENT
    [q(2), '0x', recipient, [q(200000), q(200000)], q(TRANSFER_VALUE), '0x'], // SENDER moves value
  ];
  const payload = [q(CHAIN_ID), q(nonce), account, frames,
    [[q(0), '0x', '0x', '0x'],   // witness 0: SPHINCS ARBITRARY (account verify)
     [q(0), '0x', '0x', '0x']],  // witness 1: operator secp256k1 ARBITRARY (paymaster verify)
    [q(fees.priorityFee), q(fees.maxFee), '0x'], []];
  const digest = signingHash(payload);

  const sig = sphincsSign(key.seed, ethers.getBytes(digest), 'sphincs-g');
  if (!sphincsVerify(key.pkSeed, key.pkRoot, digest, sig.sigHex, 'sphincs-g').valid)
    throw Error('SPHINCS signature failed local verification');
  payload[4][0][3] = sig.sigHex;

  let opSig = operatorWitness(operator, digest);
  if (corruptOperator) {
    const b = ethers.getBytes(opSig); b[Math.floor(b.length / 2)] ^= 0xff; opSig = ethers.hexlify(b);
  }
  payload[4][1][3] = opSig;

  const raw = encodeFrame(payload);
  return { raw, hash: ethers.keccak256(raw) };
}

async function runGood(deployer, config, paymaster, operator) {
  log('== GOOD: PQ account sponsored by the paymaster contract (both contracts) ==');
  const key = freshSphincsKey();
  const account = accountAddress(config, key.pkSeed, key.pkRoot);
  const recipient = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));
  log('    account (PQ clone)', account);
  log('    paymaster         ', paymaster);
  log('    recipient         ', recipient);

  // Pre-create the account clone via our factory (driven by the deployer EOA).
  const createData = FACTORY_ABI.encodeFunctionData('createAccount', [key.pkSeed, key.pkRoot, ethers.ZeroHash]);
  await deployerCall(deployer, config.factory, createData, 'create-account');
  if (!(await hasCode(account))) throw Error('account clone was not created');

  // Fund: account gets the value it will move; paymaster gets gas money.
  await faucetFund(account, 'account', TRANSFER_VALUE);
  await faucetFund(paymaster, 'paymaster', ethers.parseEther('0.01'));

  const aBal0 = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  const pBal0 = BigInt(await rpc('eth_getBalance', [paymaster, 'latest']));
  const rBal0 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));

  const fees = await feeParams();
  const nonce = BigInt(await rpc('eth_getTransactionCount', [account, 'pending']));
  const tx = buildSponsored(account, paymaster, recipient, nonce, key, operator, fees);
  log('    tx', tx.hash);
  const res = await rpc('eth_sendRawTransaction', [tx.raw]);
  if (res.toLowerCase() !== tx.hash.toLowerCase()) throw Error('submit hash mismatch: ' + JSON.stringify(res));
  const rc = await pollReceipt(tx.hash);
  if (!rc) throw Error('GOOD tx produced no receipt');
  const frameStatuses = (rc.frameReceipts || []).map(f => f.status);
  log('    receipt status', rc.status, 'block', rc.blockNumber, 'payer', rc.payer, 'frames', JSON.stringify(frameStatuses));
  if (BigInt(rc.status) !== 1n || frameStatuses.some(s => BigInt(s) !== 1n)) throw Error('GOOD tx did not fully succeed');

  const aBal1 = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  const pBal1 = BigInt(await rpc('eth_getBalance', [paymaster, 'latest']));
  const rBal1 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  const aDelta = aBal1 - aBal0, pDelta = pBal1 - pBal0, rDelta = rBal1 - rBal0;
  log('    account delta  ', aDelta.toString(), '(expect -' + TRANSFER_VALUE + ', value only, zero gas)');
  log('    paymaster delta', pDelta.toString(), '(expect negative = gas)');
  log('    recipient delta', rDelta.toString(), '(expect +' + TRANSFER_VALUE + ')');

  if ((rc.payer || '').toLowerCase() !== paymaster.toLowerCase()) throw Error('receipt.payer is not the paymaster contract');
  if (aDelta !== -TRANSFER_VALUE) throw Error('account was charged more than the value (it paid gas)');
  if (pDelta >= 0n) throw Error('paymaster did not pay gas');
  if (rDelta !== TRANSFER_VALUE) throw Error('recipient did not receive the value');
  log('    GOOD ok: payer == paymaster contract, account paid zero gas, recipient paid');
  return { hash: tx.hash, account, recipient, payer: rc.payer, aDelta, pDelta, rDelta, key };
}

async function runBad(deployer, config, paymaster, operator, good) {
  log('== BAD: corrupted operator signature must make the paymaster VERIFY reject ==');
  // Reuse the GOOD account (now nonce 1) with a fresh recipient; corrupt the operator sig.
  const account = good.account, key = good.key;
  const recipient = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));
  const aBal0 = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  const pBal0 = BigInt(await rpc('eth_getBalance', [paymaster, 'latest']));
  const rBal0 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));

  const fees = await feeParams();
  const nonce = BigInt(await rpc('eth_getTransactionCount', [account, 'pending']));
  const tx = buildSponsored(account, paymaster, recipient, nonce, key, operator, fees, true);
  log('    corrupted-operator tx', tx.hash);
  let submitError = null;
  try { await rpc('eth_sendRawTransaction', [tx.raw]); }
  catch (err) { submitError = { code: err.rpcCode, message: err.message }; }
  if (submitError) log('    REJECTED at admission:', JSON.stringify(submitError));
  else {
    log('    accepted structurally -> checking it never succeeds');
    const rc = await pollReceipt(tx.hash, 20);
    if (rc && BigInt(rc.status) === 1n) throw Error('corrupted-operator tx succeeded: paymaster gate is broken');
    log('    not successfully included:', rc ? 'reverted ' + rc.status : 'no receipt');
  }
  const aBal1 = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  const pBal1 = BigInt(await rpc('eth_getBalance', [paymaster, 'latest']));
  const rBal1 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  if (rBal1 !== rBal0) throw Error('recipient received value on a rejected tx');
  if (aBal1 !== aBal0) throw Error('account was charged on a rejected tx');
  if (pBal1 !== pBal0) throw Error('paymaster was charged on a rejected tx');
  log('    BAD ok: nothing moved, nobody charged');
  return { hash: tx.hash, outcome: submitError || { includedSuccessfully: false } };
}

async function main() {
  log('[init] keccak + protocol');
  await initCrypto();
  await assertChain();
  log('[deployer] fresh faucet-funded EOA');
  const deployer = ethers.Wallet.createRandom();
  const operator = ethers.Wallet.createRandom(); // the paymaster's authorizing operator key
  log('    deployer', deployer.address);
  log('    operator', operator.address, '(secp256k1, baked into the paymaster)');
  await faucetFund(deployer.address, 'deployer', ethers.parseEther('0.05'));
  log('[contracts] deploy exec-only impl + factory + paymaster via Arachnid');
  const { impl, factory, paymaster, config } = await deployContracts(deployer, operator);

  const good = await runGood(deployer, config, paymaster, operator);
  const bad = await runBad(deployer, config, paymaster, operator, good);

  log('');
  log('PoC daisugi PQ + paymaster GREEN on chain', CHAIN_ID.toString());
  log('  exec-only impl:', impl);
  log('  factory       :', factory);
  log('  paymaster     :', paymaster, '(operator', operator.address + ')');
  log('  GOOD tx       :', good.hash, 'https://explorer.daisugi.fyi/tx/' + good.hash);
  log('  account       :', good.account, '(PQ clone, paid zero gas)');
  log('  payer         :', good.payer, '(the paymaster contract)');
  log('  deltas        : account', good.aDelta.toString(), '| paymaster', good.pDelta.toString(), '| recipient', good.rDelta.toString());
  log('  BAD tx        :', bad.hash, 'rejected, nothing moved');
  log('  Proven: a PQ (SPHINCS) account sponsored by a paymaster CONTRACT, both contracts and no EOA rail roles, works live on Daisugi via Gen1 in-frame.');
}

main().catch(err => { console.error('FAILED:', err.message); process.exitCode = 1; });
