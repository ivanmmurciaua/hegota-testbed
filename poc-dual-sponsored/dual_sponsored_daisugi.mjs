// DAISUGI HALF of a dual-network "sponsored post-quantum ETH send" PoC (Nethermind,
// chainId 1337, https://daisugi.fyi/rpc). Mirrors the GREEN ethrex half end to end,
// but in Daisugi's own dialect (SPHINCS-G hash-based account, native-opcode frames,
// Gen1 eth_sendRawTransaction with inline witnesses).
//
// End to end:
//   1. a SPHINCS-G account at a COUNTERFACTUAL CREATE2 address (pure function of its
//      key + our factory/impl, no EOA in the derivation), computed before any deploy;
//   2. it RECEIVES ETH at that address while it still has no code;
//   3. it is DEPLOYED WITHOUT any EOA, via an openSponsor frame transaction: an
//      openSponsor CONTRACT is the frame-tx sender and pays the deploy gas. Its VERIFY
//      frame APPROVEs exec+payment unconditionally (no signature, no witness read); a
//      DEFAULT frame calls factory.createAccount(pkSeed,pkRoot,salt) to CREATE2-deploy
//      the counterfactual SPHINCS clone. No EOA signs TX1;
//   4. then a NATIVE ETH SEND to a fresh recipient whose gas is paid by a funded k1
//      paymaster CONTRACT (operator ECDSA baked in code), NOT self-pay, via the Gen1
//      in-frame path: frames [VERIFY account SPHINCS flags 0x2][VERIFY paymaster
//      flags 0x1][SENDER recipient value], witnesses idx0 SPHINCS, idx1 operator ECDSA.
//
// CRITICAL (proven in prior work, not rediscovered here): on Daisugi the sponsored /
// paymaster PQ path works ONLY via Gen1 (eth_sendRawTransaction, inline witnesses),
// never via the aggregated Gen2 eth_sendProofWrapper. Everything here is Gen1.
//
// This PoC imports the hegota-testbed daisugi backend modules READ-ONLY
// (../backends/daisugi/pocs/pq_frame_lib.mjs, pq_account_gen.mjs) and does not modify
// anything under backends/ or core/. The ONLY new
// pieces are the Daisugi openSponsor contract (authored below) and the three-mode driver
// (derive / fund / execute) that lets a single cross-chain orchestrator gate the no-EOA
// deploy on the account actually being funded. The PROVEN rail logic (SPHINCS signing,
// frame building, gas, checks) is UNCHANGED from the green single-run version; only the
// orchestration seams (JSON state in/out, which step runs in which mode) were added.
//
// Modes (argv[2], default "all" = derive -> fund -> execute in one process):
//   derive   fresh key + recipient, predicted CREATE2 addresses, counterfactual account,
//            write <state>; prints the account + recipient. No chain writes.
//   fund     read <state>; deploy the infra via Arachnid, endow sponsor/paymaster/account
//            (faucet default, env funder fallback); write deployed addrs into <state>.
//   execute  read <state>; the two zero-gas rail txs (no-EOA sponsored deploy + paymaster
//            send) plus the two negatives; write <result>.
//
// The ONLY EOA in the flow is the faucet-funded deployer/funder: it deploys infra via
// Arachnid and funds cold roles, and it signs NO rail transaction. No key is written to a
// tracked file (the local state/result files are gitignored, never committed): the SPHINCS
// key is regenerated from a fresh seed kept in the local state for this run, the operator
// ECDSA key is kept in the local state, the deployer EOA is generated fresh in memory for
// the fund step.
//
// Run: driven by run_dual.sh / orchestrate.py. Direct: node dual_sponsored_daisugi.mjs all

import { writeFileSync, readFileSync, renameSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ethers, rpc, log, sleep, initCrypto, assertChain, feeParams, pollReceipt, hasCode,
  deployViaArachnid, compileYul, freshSphincsKey, sphincsSign, sphincsVerify,
  operatorWitness, k1Witness, accountAddress, signingHash, encodeFrame, quantity as q,
  FACTORY_ABI, CHAIN_ID, FAUCET, ARACHNID,
} from '../backends/daisugi/pocs/pq_frame_lib.mjs';
import {
  buildAccountRuntime, buildPaymasterRuntime, deployInitCode, factoryYul, SPHINCS_VERIFIER,
} from '../backends/daisugi/pocs/pq_account_gen.mjs';

// ---- parameters -----------------------------------------------------------------
const VALUE = 1_000_000n;                 // wei sent onward to the recipient
const SPONSOR_GAS = ethers.parseEther('0.02');   // sponsor's deploy-gas budget
const PM_ENDOW = ethers.parseEther('0.02');      // paymaster's gas budget
const ACCT_VERIFY_GAS = 415000n;          // SPHINCS VERIFY frame budget
const PAY_VERIFY_GAS = 70000n;            // paymaster VERIFY frame (ecrecover) budget

const IMPL_SALT = ethers.id('r1do.dual.daisugi.impl.exec2.v1');
const FACT_SALT = ethers.id('r1do.dual.daisugi.factory.v1');
const SPONSOR_SALT = ethers.id('r1do.dual.daisugi.opensponsor.v1');
const PM_SALT = ethers.id('r1do.dual.daisugi.paymaster.v1');

const HERE = dirname(fileURLToPath(import.meta.url));
const STATE_DIR = process.env.DUAL_STATE_DIR || HERE;
const STATE_PATH = join(STATE_DIR, 'daisugi.state.json');
const RESULT_PATH = join(STATE_DIR, 'daisugi.result.json');

const bigints = (obj) => JSON.stringify(obj, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
const loadState = () => JSON.parse(readFileSync(STATE_PATH, 'utf8'));
const saveState = (s) => { writeFileSync(STATE_PATH + '.tmp', bigints(s)); renameSync(STATE_PATH + '.tmp', STATE_PATH); };
const saveResult = (r) => { writeFileSync(RESULT_PATH + '.tmp', bigints(r)); renameSync(RESULT_PATH + '.tmp', RESULT_PATH); };

// cold-faucet telemetry (honest reporting): labels whose env-funder fallback fired.
const coldFaucetRoles = [];

// ---- the NEW piece: a Daisugi openSponsor runtime -------------------------------
function assembler() {
  const code = [];
  const labels = new Map();
  const jumps = [];
  const op = byte => code.push(byte);
  const push = value => {
    let hex = typeof value === 'number' ? value.toString(16) : value;
    if (hex.length % 2) hex = `0${hex}`;
    const bytes = Buffer.from(hex, 'hex');
    if (!bytes.length || bytes.length > 32) throw Error('invalid PUSH width');
    op(0x5f + bytes.length);
    code.push(...bytes);
  };
  const jump = (label, conditional = true) => {
    op(0x61); jumps.push({ label, offset: code.length }); code.push(0, 0);
    op(conditional ? 0x57 : 0x56);
  };
  const label = name => { labels.set(name, code.length); op(0x5b); };
  const requireTrue = () => { op(0x15); jump('reject'); };
  const finalize = () => {
    for (const { label: name, offset } of jumps) {
      const dest = labels.get(name);
      if (dest === undefined || dest > 65535) throw Error('invalid jump target');
      code[offset] = dest >> 8; code[offset + 1] = dest & 0xff;
    }
    return '0x' + Buffer.from(code).toString('hex');
  };
  return { op, push, jump, label, requireTrue, finalize };
}

// openSponsor runtime: on a native VERIFY frame (CALLER == 0xaa node sentinel) it
// APPROVEs scope 3 (EXECUTION + PAYMENT) unconditionally; any other caller may only
// fund it (empty calldata -> STOP). Mirrors ethrex's 12-byte openSponsor in Daisugi's
// native-opcode dialect.
function buildSponsorRuntime() {
  const a = assembler();
  a.op(0x33); a.push(0xaa); a.op(0x14); a.jump('verify');
  a.op(0x36); a.op(0x15); a.requireTrue(); a.op(0x00);
  a.label('verify');
  a.push(3); a.push(0); a.push(0); a.op(0xaa);
  a.label('reject'); a.push(0); a.push(0); a.op(0xfd);
  return a.finalize();
}

// ---- helpers --------------------------------------------------------------------
const checks = {};
const check = (name, ok) => { checks[name] = !!ok; log(`    [${ok ? 'PASS' : 'FAIL'}] ${name}`); };

async function faucetOnce(address, label) {
  try {
    const fr = await fetch(FAUCET, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address }) });
    log(`    [${label}] faucet`, fr.status, (await fr.text()).slice(0, 90));
  } catch (err) { log(`    [${label}] faucet request failed:`, err.message); }
}

// Fund `address` to >= minWei. Faucet first (keeps contract roles EOA-free); only if
// the faucet is cold does the funder source (the deployer EOA, or an env funder key on
// the chain) top it up. Records cold-faucet fallbacks for honest reporting.
async function ensureFunded(address, minWei, label, funder) {
  let bal = BigInt(await rpc('eth_getBalance', [address, 'latest']));
  if (bal >= minWei) { log(`    [${label}] already funded`, bal.toString()); return bal; }
  await faucetOnce(address, label);
  for (let i = 0; i < 20 && bal < minWei; i++) { bal = BigInt(await rpc('eth_getBalance', [address, 'latest'])); if (bal < minWei) await sleep(2000); }
  if (bal >= minWei) { log(`    [${label}] funded by faucet`, bal.toString()); return bal; }
  if (funder) {
    log(`    [${label}] faucet cold; env/deployer funder tops up (funder role, no rail tx)`);
    coldFaucetRoles.push(label);
    await deployerSend(funder, address, minWei - bal, label);
    bal = BigInt(await rpc('eth_getBalance', [address, 'latest']));
  }
  if (bal < minWei) throw Error(`[${label}] could not fund to ${minWei} (have ${bal})`);
  return bal;
}

// A plain value transfer from a funded EOA via a frame tx: VERIFY self (k1, approve
// both) + SENDER move value. Used only to top up a cold faucet role.
async function deployerSend(deployer, to, value, label) {
  const { priorityFee, maxFee } = await feeParams();
  const nonce = BigInt(await rpc('eth_getTransactionCount', [deployer.address, 'pending']));
  const frames = [
    [q(1), q(3), deployer.address, [q(100000), '0x'], '0x', '0x'],
    [q(2), '0x', to, [q(100000), q(100000)], q(value), '0x'],
  ];
  const payload = [q(CHAIN_ID), q(nonce), deployer.address, frames,
    [[q(1), deployer.address, '0x', '0x']], [q(priorityFee), q(maxFee), '0x'], []];
  const digest = signingHash(payload);
  payload[4][0][3] = k1Witness(deployer, digest);
  const hash = await rpc('eth_sendRawTransaction', [encodeFrame(payload)]);
  const rc = await pollReceipt(hash);
  if (!rc || BigInt(rc.status) !== 1n) throw Error(`[${label}] funder top-up failed ${JSON.stringify(rc && rc.status)}`);
  log(`    [${label}] funder top-up`, hash);
  return hash;
}

// Bootstrap the deployer EOA: faucet first, optional env funder key (PQ_DAISUGI_FUNDER_KEY)
// if the faucet is cold, so the PoC still runs.
async function fundDeployer(deployer, minWei) {
  let bal = BigInt(await rpc('eth_getBalance', [deployer.address, 'latest']));
  if (bal >= minWei) return bal;
  await faucetOnce(deployer.address, 'deployer');
  for (let i = 0; i < 20 && bal < minWei; i++) { bal = BigInt(await rpc('eth_getBalance', [deployer.address, 'latest'])); if (bal < minWei) await sleep(2000); }
  if (bal >= minWei) { log('    [deployer] funded by faucet', bal.toString()); return bal; }
  const fk = process.env.PQ_DAISUGI_FUNDER_KEY;
  if (fk) {
    log('    [deployer] faucet cold; env funder PQ_DAISUGI_FUNDER_KEY bootstraps the deployer');
    coldFaucetRoles.push('deployer');
    const envFunder = new ethers.Wallet(fk);
    await deployerSend(envFunder, deployer.address, minWei - bal, 'deployer');
    bal = BigInt(await rpc('eth_getBalance', [deployer.address, 'latest']));
  }
  if (bal < minWei) throw Error(`[deployer] faucet cold and no env funder; cannot bootstrap (have ${bal})`);
  return bal;
}

// TX1: the no-EOA sponsored deploy. sender = the openSponsor contract (the payer).
function buildSponsoredDeploy(sponsor, factory, key, nonce, fees) {
  const createData = FACTORY_ABI.encodeFunctionData('createAccount', [key.pkSeed, key.pkRoot, ethers.ZeroHash]);
  const frames = [
    [q(1), q(3), sponsor, [q(120000), '0x'], '0x', '0x'],
    ['0x', '0x', factory, [q(150000), q(600000)], '0x', createData],
  ];
  const payload = [q(CHAIN_ID), q(nonce), sponsor, frames,
    [['0x', '0x', '0x', '0x']], [q(fees.priorityFee), q(fees.maxFee), '0x'], []];
  const raw = encodeFrame(payload);
  return { raw, hash: ethers.keccak256(raw) };
}

// TX2: the paymaster-sponsored SPHINCS spend.
function buildSpend(account, paymaster, recipient, nonce, key, operator, fees, { corruptAccount = false, corruptOperator = false } = {}) {
  const frames = [
    [q(1), q(2), account,   [q(ACCT_VERIFY_GAS), '0x'], '0x', '0x'],
    [q(1), q(1), paymaster, [q(PAY_VERIFY_GAS), '0x'], '0x', '0x'],
    [q(2), '0x', recipient, [q(200000), q(200000)], q(VALUE), '0x'],
  ];
  const payload = [q(CHAIN_ID), q(nonce), account, frames,
    [[q(0), '0x', '0x', '0x'], [q(0), '0x', '0x', '0x']],
    [q(fees.priorityFee), q(fees.maxFee), '0x'], []];
  const digest = signingHash(payload);

  const sig = sphincsSign(key.seed, ethers.getBytes(digest), 'sphincs-g');
  if (!sphincsVerify(key.pkSeed, key.pkRoot, digest, sig.sigHex, 'sphincs-g').valid)
    throw Error('SPHINCS signature failed local verification');
  let sphincsSigHex = sig.sigHex;
  if (corruptAccount) {
    const b = ethers.getBytes(sphincsSigHex); b[Math.floor(b.length / 2)] ^= 0xff; sphincsSigHex = ethers.hexlify(b);
    if (sphincsVerify(key.pkSeed, key.pkRoot, digest, sphincsSigHex, 'sphincs-g').valid) throw Error('account corruption still verifies locally');
  }
  payload[4][0][3] = sphincsSigHex;

  let opSig = operatorWitness(operator, digest);
  if (corruptOperator) { const b = ethers.getBytes(opSig); b[Math.floor(b.length / 2)] ^= 0xff; opSig = ethers.hexlify(b); }
  payload[4][1][3] = opSig;

  const raw = encodeFrame(payload);
  return { raw, hash: ethers.keccak256(raw) };
}

// Predict the Arachnid CREATE2 address for a creation bytecode + salt (no deploy).
const arachnidAddress = (creationBytecode, salt) => ethers.getCreate2Address(ARACHNID, salt, ethers.keccak256(creationBytecode));

// Recompute the four infra creation bytecodes deterministically (shared by derive/fund).
function infraArtifacts(operatorAddress) {
  const implRuntime = buildAccountRuntime(2, SPHINCS_VERIFIER, { soleWitness: false });
  const implInit = deployInitCode(implRuntime);
  const impl = arachnidAddress(implInit, IMPL_SALT);
  const factoryInit = compileYul(factoryYul(impl), 'AccountFactory');
  const factory = arachnidAddress(factoryInit, FACT_SALT);
  const payRuntime = buildPaymasterRuntime(operatorAddress);
  const payInit = deployInitCode(payRuntime);
  const paymaster = arachnidAddress(payInit, PM_SALT);
  const sponsorRuntime = buildSponsorRuntime();
  const sponsorInit = deployInitCode(sponsorRuntime);
  const sponsor = arachnidAddress(sponsorInit, SPONSOR_SALT);
  return { implRuntime, implInit, impl, factoryInit, factory, payRuntime, payInit, paymaster,
    sponsorRuntime, sponsorInit, sponsor };
}

// ---- MODE: derive ---------------------------------------------------------------
async function derive() {
  log('[daisugi derive] keccak + crypto; assert chain');
  await initCrypto();
  await assertChain();
  log(`    Daisugi chainId ${CHAIN_ID}  faucet ${FAUCET}`);

  const operator = ethers.Wallet.createRandom(); // paymaster's authorizing key, baked in code
  const inf = infraArtifacts(operator.address);
  log(`    openSponsor runtime (${inf.sponsorRuntime.length / 2 - 1} B): ${inf.sponsorRuntime}`);

  const key = freshSphincsKey();
  const account = accountAddress({ implementation: inf.impl, factory: inf.factory }, key.pkSeed, key.pkRoot);
  const recipient = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));
  log(`    pkSeed ${key.pkSeed}  pkRoot ${key.pkRoot}`);
  log(`    predicted impl ${inf.impl}  factory ${inf.factory}`);
  log(`    predicted paymaster ${inf.paymaster} (operator ${operator.address})  sponsor ${inf.sponsor}`);
  log(`    counterfactual account (CREATE2 via factory, salt 0, no EOA) ${account}`);
  if (await hasCode(account)) throw Error(`counterfactual account ${account} already has code`);

  const state = {
    chain: 'daisugi', rpc: process.env.PQ_RPC_URL || 'https://daisugi.fyi/rpc', chainId: CHAIN_ID.toString(),
    seed: Buffer.from(key.seed).toString('hex'), pkSeed: key.pkSeed, pkRoot: key.pkRoot,
    account, recipient, operatorKey: operator.privateKey, operator: operator.address,
    impl: inf.impl, factory: inf.factory, paymaster: inf.paymaster, sponsor: inf.sponsor,
    verifier: SPHINCS_VERIFIER, need: VALUE.toString(), sponsorGas: SPONSOR_GAS.toString(),
    pmEndow: PM_ENDOW.toString(), value: VALUE.toString(),
  };
  saveState(state);
  log(`\n[derive] state written -> ${STATE_PATH}`);
  log(`    FUND THIS ACCOUNT: ${account}  (>= ${VALUE} wei)   recipient ${recipient}`);
  return state;
}

// ---- MODE: fund -----------------------------------------------------------------
async function fund() {
  await initCrypto();
  await assertChain();
  const state = loadState();
  const operator = new ethers.Wallet(state.operatorKey);
  log(`[daisugi fund] account ${state.account}  operator ${operator.address}`);

  // deployer/funder EOA (the ONLY EOA; faucet-funded; signs NO rail tx) ----------------
  const deployer = ethers.Wallet.createRandom();
  log('    fresh deployer/funder EOA', deployer.address, '(deploys infra, funds cold roles, signs NO rail tx)');
  await fundDeployer(deployer, ethers.parseEther('0.3'));

  // deploy the infrastructure via Arachnid (setup; deployer pays) ----------------------
  const inf = infraArtifacts(operator.address);
  const impl = await deployViaArachnid(deployer, inf.implInit, IMPL_SALT, 'impl');
  check('exec-only impl runtime on-chain == our generator', (await rpc('eth_getCode', [impl, 'latest'])).toLowerCase() === inf.implRuntime.toLowerCase());
  check('impl deployed at predicted address', impl.toLowerCase() === state.impl.toLowerCase());

  const factory = await deployViaArachnid(deployer, inf.factoryInit, FACT_SALT, 'factory');
  check('factory deployed at predicted address', factory.toLowerCase() === state.factory.toLowerCase());

  const paymaster = await deployViaArachnid(deployer, inf.payInit, PM_SALT, 'paymaster');
  check('paymaster runtime on-chain == our generator', (await rpc('eth_getCode', [paymaster, 'latest'])).toLowerCase() === inf.payRuntime.toLowerCase());
  check('paymaster deployed at predicted address', paymaster.toLowerCase() === state.paymaster.toLowerCase());

  const sponsor = await deployViaArachnid(deployer, inf.sponsorInit, SPONSOR_SALT, 'openSponsor');
  check('openSponsor runtime on-chain == our generator', (await rpc('eth_getCode', [sponsor, 'latest'])).toLowerCase() === inf.sponsorRuntime.toLowerCase());
  check('openSponsor deployed at predicted address', sponsor.toLowerCase() === state.sponsor.toLowerCase());

  // fund the sponsor (deploy gas), the paymaster (send gas), the account (value) --------
  const sponsorBal0 = await ensureFunded(sponsor, SPONSOR_GAS, 'sponsor', deployer);
  check('openSponsor endowed with a deploy-gas budget', sponsorBal0 >= SPONSOR_GAS);
  const pmBal = await ensureFunded(paymaster, PM_ENDOW, 'paymaster', deployer);
  check('paymaster endowed with a gas budget', pmBal >= PM_ENDOW);

  log('\n[fund] the counterfactual account receives ETH (pre-deploy)');
  const acctFunded = await ensureFunded(state.account, VALUE, 'account', deployer);
  check('account received ETH at the counterfactual address', acctFunded >= VALUE);
  check('account STILL has no code after funding (counterfactual)', !(await hasCode(state.account)));

  state.impl = impl; state.factory = factory; state.paymaster = paymaster; state.sponsor = sponsor;
  state.account_funded_wei = acctFunded.toString();
  state.cold_faucet_used = coldFaucetRoles.length > 0;
  state.cold_faucet_roles = [...coldFaucetRoles];
  state.fund_checks = { ...checks };
  saveState(state);
  log(`[daisugi fund] account funded (${acctFunded} wei); infra ready; cold-faucet fallback used: ${state.cold_faucet_used}`);
  return state;
}

// ---- MODE: execute --------------------------------------------------------------
async function execute() {
  await initCrypto();
  await assertChain();
  const state = loadState();
  const operator = new ethers.Wallet(state.operatorKey);
  const key = { seed: Uint8Array.from(Buffer.from(state.seed, 'hex')), pkSeed: state.pkSeed, pkRoot: state.pkRoot };
  const { account, paymaster, sponsor, factory, recipient } = state;
  log(`[daisugi execute] account ${account}  sponsor ${sponsor}  paymaster ${paymaster}`);

  // listener gate: the account must already be funded (orchestrator also gates) --------
  const acctBal0 = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  check('account funded before deploy (listener gate)', acctBal0 >= VALUE);
  if (acctBal0 < VALUE) throw Error(`execute called but account not funded (${acctBal0} wei)`);

  // NO-EOA SPONSORED DEPLOY (TX1) ------------------------------------------------------
  log('\n[deploy TX1] no-EOA sponsored deploy via the openSponsor', sponsor);
  const fees1 = await feeParams();
  const nonce1 = BigInt(await rpc('eth_getTransactionCount', [sponsor, 'pending']));
  const tx1 = buildSponsoredDeploy(sponsor, factory, key, nonce1, fees1);
  const sponsorBefore = BigInt(await rpc('eth_getBalance', [sponsor, 'latest']));
  const funderBeforeDeploy = acctBal0; // account balance pre-deploy
  const acctBalBefore = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  log('    submitting TX1', tx1.hash);
  const res1 = await rpc('eth_sendRawTransaction', [tx1.raw]);
  if (res1.toLowerCase() !== tx1.hash.toLowerCase()) throw Error('TX1 submit hash mismatch: ' + JSON.stringify(res1));
  const drc = await pollReceipt(tx1.hash);
  if (!drc) throw Error('deploy TX1 produced no receipt');
  log('    TX1 receipt:', JSON.stringify({ status: drc.status, from: drc.from, payer: drc.payer, gasUsed: drc.gasUsed, frames: (drc.frameReceipts || []).map(f => f.status) }));
  const d_from = (drc.from || '').toLowerCase();
  const d_payer = (drc.payer || '').toLowerCase();
  const sponsorAfter = BigInt(await rpc('eth_getBalance', [sponsor, 'latest']));
  const acctBalAfter = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  const acctCodeNow = await hasCode(account);

  check('deploy TX1 mined status 0x1', BigInt(drc.status) === 1n);
  check('deploy TX1 all frames succeeded', (drc.frameReceipts || []).every(f => BigInt(f.status) === 1n));
  check('deploy TX1 sender is the SPONSOR CONTRACT (no EOA)', d_from === sponsor.toLowerCase());
  check('account now HAS code (deployed)', acctCodeNow);
  check('account balance survived the deploy (CREATE2 kept the received ETH)', acctBalAfter === acctBalBefore);
  check('SPONSOR paid the deploy gas (its balance dropped > 0)', sponsorAfter < sponsorBefore);
  if (d_payer) check('deploy payer == the SPONSOR (not an EOA)', d_payer === sponsor.toLowerCase());

  // NEGATIVE A: tampered SPHINCS account witness -> rejected at admission ---------------
  log('\n[negative A] tampered SPHINCS account witness (submit; expect admission rejection)');
  const rnegA = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));
  const feesNA = await feeParams();
  const nonceNA = BigInt(await rpc('eth_getTransactionCount', [account, 'pending']));
  const txNA = buildSpend(account, paymaster, rnegA, nonceNA, key, operator, feesNA, { corruptAccount: true });
  let rejA = false; let errA = null;
  try { await rpc('eth_sendRawTransaction', [txNA.raw]); } catch (err) { rejA = true; errA = { code: err.rpcCode, message: err.message }; }
  if (rejA) log('    REJECTED at admission:', JSON.stringify(errA));
  else { const rc = await pollReceipt(txNA.hash, 15); rejA = !(rc && BigInt(rc.status) === 1n); log('    not successfully included:', rc ? 'reverted ' + rc.status : 'no receipt'); }
  check('NEG A: tampered SPHINCS witness rejected', rejA);
  check('NEG A: recipient got nothing', BigInt(await rpc('eth_getBalance', [rnegA, 'latest'])) === 0n);

  // NEGATIVE B: tampered operator witness -> paymaster gate rejects at admission --------
  log('\n[negative B] tampered operator witness (submit; expect admission rejection)');
  const rnegB = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));
  const feesNB = await feeParams();
  const nonceNB = BigInt(await rpc('eth_getTransactionCount', [account, 'pending']));
  const txNB = buildSpend(account, paymaster, rnegB, nonceNB, key, operator, feesNB, { corruptOperator: true });
  let rejB = false; let errB = null;
  try { await rpc('eth_sendRawTransaction', [txNB.raw]); } catch (err) { rejB = true; errB = { code: err.rpcCode, message: err.message }; }
  if (rejB) log('    REJECTED at admission:', JSON.stringify(errB));
  else { const rc = await pollReceipt(txNB.hash, 15); rejB = !(rc && BigInt(rc.status) === 1n); log('    not successfully included:', rc ? 'reverted ' + rc.status : 'no receipt'); }
  check('NEG B: tampered operator witness rejected', rejB);
  check('NEG B: recipient got nothing', BigInt(await rpc('eth_getBalance', [rnegB, 'latest'])) === 0n);

  // POSITIVE: paymaster-sponsored SPHINCS send, account pays ZERO gas ------------------
  log('\n[spend TX2] paymaster-sponsored SPHINCS send ->', recipient);
  const fees2 = await feeParams();
  const nonce2 = BigInt(await rpc('eth_getTransactionCount', [account, 'pending']));
  const tx2 = buildSpend(account, paymaster, recipient, nonce2, key, operator, fees2);
  const aBal0 = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  const pBal0 = BigInt(await rpc('eth_getBalance', [paymaster, 'latest']));
  const rBal0 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  log('    submitting TX2', tx2.hash);
  const res2 = await rpc('eth_sendRawTransaction', [tx2.raw]);
  if (res2.toLowerCase() !== tx2.hash.toLowerCase()) throw Error('TX2 submit hash mismatch: ' + JSON.stringify(res2));
  const src = await pollReceipt(tx2.hash);
  if (!src) throw Error('spend TX2 produced no receipt');
  log('    TX2 receipt:', JSON.stringify({ status: src.status, from: src.from, payer: src.payer, gasUsed: src.gasUsed, frames: (src.frameReceipts || []).map(f => f.status) }));
  const s_from = (src.from || '').toLowerCase();
  const s_payer = (src.payer || '').toLowerCase();
  const aBal1 = BigInt(await rpc('eth_getBalance', [account, 'latest']));
  const pBal1 = BigInt(await rpc('eth_getBalance', [paymaster, 'latest']));
  const rBal1 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  const aDelta = aBal1 - aBal0, pDelta = pBal1 - pBal0, rDelta = rBal1 - rBal0;
  log(`    account delta ${aDelta}  paymaster delta ${pDelta}  recipient delta ${rDelta}  (value ${VALUE})`);

  check('POS: spend mined status 0x1', BigInt(src.status) === 1n);
  check('POS: spend all frames succeeded', (src.frameReceipts || []).every(f => BigInt(f.status) === 1n));
  check('POS: receipt sender is the ACCOUNT (not the paymaster)', s_from === account.toLowerCase());
  check('POS: ACCOUNT paid ZERO gas (delta == exactly -value)', aDelta === -VALUE);
  check('POS: recipient received the full value (no gas loss)', rDelta === VALUE);
  check('POS: PAYMASTER paid the gas (its balance dropped > 0)', pDelta < 0n);
  if (s_payer) check('POS: spend payer == the PAYMASTER (not the account)', s_payer === paymaster.toLowerCase());

  const allGreen = Object.values(checks).every(Boolean);
  const result = {
    chain: 'daisugi', rpc: state.rpc, chainId: state.chainId, account, recipient,
    sponsor, factory, impl: state.impl, paymaster, operator: operator.address, verifier: SPHINCS_VERIFIER,
    value: VALUE.toString(), funded_wei: (state.account_funded_wei || acctBal0.toString()),
    cold_faucet_used: !!state.cold_faucet_used, cold_faucet_roles: state.cold_faucet_roles || [],
    deploy_tx: tx1.hash, deploy_from: d_from, deploy_payer: d_payer, deploy_status: drc.status, deploy_gas_used: drc.gasUsed,
    spend_tx: tx2.hash, spend_from: s_from, spend_payer: s_payer, spend_status: src.status, spend_gas_used: src.gasUsed,
    account_delta: aDelta.toString(), paymaster_delta: pDelta.toString(), recipient_received: rDelta.toString(),
    checks, all_green: allGreen,
    explorer: { deploy: 'https://explorer.daisugi.fyi/tx/' + tx1.hash, spend: 'https://explorer.daisugi.fyi/tx/' + tx2.hash },
  };
  saveResult(result);

  log('\n== daisugi checks ==');
  for (const [name, ok] of Object.entries(checks)) log(`  [${ok ? 'PASS' : 'FAIL'}] ${name}`);
  if (allGreen) {
    log('\nDAISUGI HALF GREEN: counterfactual -> fund -> no-EOA openSponsor deploy -> ' +
        'paymaster-sponsored SPHINCS send, all observed in receipts on https://daisugi.fyi/rpc (Gen1).');
  } else {
    throw Error('DAISUGI HALF FAILED: see the checks above (a failure is the signal).');
  }
  return result;
}

// ---- dispatch -------------------------------------------------------------------
const mode = process.argv[2] || 'all';
const run = mode === 'derive' ? derive
  : mode === 'fund' ? fund
  : mode === 'execute' ? execute
  : mode === 'all' ? (async () => { await derive(); await fund(); await execute(); })
  : null;
if (!run) { console.error(`unknown mode ${mode}; use derive | fund | execute | all`); process.exitCode = 1; }
else run().catch(err => { console.error('\nFAILED:', err.message); if (err.full) console.error('  rpc:', JSON.stringify(err.full)); process.exitCode = 1; });
