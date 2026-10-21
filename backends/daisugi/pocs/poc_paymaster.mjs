// Daisugi PoC: frame-native THIRD-PARTY PAYMASTER via the Gen1 native path.
//
// This proves the paymaster MECHANISM on Daisugi: a sender account approves only
// EXECUTION in a VERIFY frame (flags 0x2, target = sender), a separate paymaster
// approves PAYMENT in its own VERIFY frame (flags 0x1, target = paymaster), and a
// SENDER frame moves value. The paymaster pays the gas; the sender pays none.
//
// It uses ECDSA (secp256k1) EOAs on purpose, to isolate the frame mechanics. The
// Nethermind frame executor runs a built-in default VERIFY code for a frame whose
// target has no contract code: it checks an inline SECP256K1 signature by the frame
// target, then APPROVEs that frame's scope. So two plain EOAs (sender, paymaster)
// are enough; no custom contracts.
//
// Submission is the Gen1 native path: eth_sendRawTransaction with a 7-element frame
// envelope [chainId, nonce, sender, frames, witnesses, fees, blobs] and the
// signatures carried INLINE in witnesses[]. The Gen2 aggregated path
// (eth_sendProofWrapper) does NOT accept a multi-VERIFY paymaster layout.
//
// Still open (NOT covered here): a post-quantum (SPHINCS) account plus paymaster.
// Gen1 verifies the account signature in-frame, and SPHINCS is gas-heavy; the cheap
// Gen2 aggregated path rejects the paymaster layout. So PQ + paymaster is a separate
// step. This PoC is the k1 checkpoint of the frame-native mechanism only.
//
// Pure ethers (no vendor_ref); it needs node_modules from ./backends/daisugi/setup.sh.
// Exit 0 only if GOOD pays gas from the paymaster (sender charged value only) AND
// BAD (corrupted paymaster signature) is rejected with nobody charged.
import * as ethers from 'ethers';

const RPC = process.env.PQ_RPC_URL || 'https://daisugi.fyi/rpc';
const FAUCET = process.env.PQ_FAUCET_URL || 'https://daisugi.fyi/api/faucet';
const CHAIN_ID = BigInt(process.env.PQ_CHAIN_ID || '1337');
const TRANSFER_VALUE = 123n; // tiny value moved by the SENDER frame (wei)

const log = (...a) => console.log(...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const q = v => BigInt(v) === 0n ? '0x' : ethers.toBeHex(v);

async function rpc(method, params = []) {
  const r = await fetch(RPC, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await r.json();
  if (body.error) { const err = Error(body.error.message); err.rpcCode = body.error.code; err.full = body.error; throw err; }
  return body.result;
}

async function faucetFund(address, label) {
  try {
    const fr = await fetch(FAUCET, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address }) });
    log(`    [${label}] faucet`, fr.status, (await fr.text()).slice(0, 110));
  } catch (err) { log(`    [${label}] faucet request failed:`, err.message); }
  let funded = 0n;
  for (let i = 0; i < 30 && funded === 0n; i++) { funded = BigInt(await rpc('eth_getBalance', [address, 'latest'])); if (funded === 0n) await sleep(2000); }
  if (funded === 0n) throw Error(`[${label}] not funded (faucet cooldown or outage)`);
  return funded;
}

async function pollReceipt(hash, tries = 60) {
  for (let i = 0; i < tries; i++) {
    const rc = await rpc('eth_getTransactionReceipt', [hash]);
    if (rc) return rc;
    await sleep(2000);
  }
  return null;
}

// Build the 7-element Gen1 frame envelope and the canonical sig hash.
// frames: [VERIFY exec target=sender][VERIFY pay target=paymaster][SENDER move value]
// witnesses: [ [1, sender, '', sig], [1, paymaster, '', sig] ] (scheme 1 = SECP256K1)
function buildEnvelope(sender, paymaster, recipient, nonce, priorityFee, maxFee, value) {
  const frames = [
    [q(1), q(2), sender,    [q(150000), '0x'],       '0x',    '0x'],   // VERIFY approve EXECUTION, target = sender
    [q(1), q(1), paymaster, [q(150000), '0x'],       '0x',    '0x'],   // VERIFY approve PAYMENT, target = paymaster
    [q(2), '0x', recipient, [q(100000), q(100000)],  q(value), '0x'],  // SENDER executes as the sender account
  ];
  const payload = [q(CHAIN_ID), q(nonce), sender, frames,
    [[q(1), sender, '0x', '0x'], [q(1), paymaster, '0x', '0x']],
    [q(priorityFee), q(maxFee), '0x'], []];
  const encode = p => '0x06' + ethers.encodeRlp(p).slice(2);
  // Canonical sig hash: witness signature bytes stay blank (empty msg) while signing.
  const sigHash = ethers.keccak256(encode(payload));
  return { payload, encode, sigHash };
}

const witnessSig = (wallet, sigHash) => {
  const s = wallet.signingKey.sign(sigHash);
  return ethers.concat([ethers.toBeHex(s.yParity, 1), s.r, s.s]); // v(1) || r(32) || s(32), recid 0/1
};

async function common() {
  const sender = ethers.Wallet.createRandom();
  const paymaster = ethers.Wallet.createRandom();
  const recipient = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));
  log('    sender   ', sender.address);
  log('    paymaster', paymaster.address);
  log('    recipient', recipient);
  await faucetFund(sender.address, 'sender');     // sender only needs the value, not gas
  await faucetFund(paymaster.address, 'paymaster'); // paymaster pays the gas
  const block = await rpc('eth_getBlockByNumber', ['latest', false]);
  const priorityFee = 1000000000n, maxFee = BigInt(block.baseFeePerGas) * 2n + priorityFee;
  return { sender, paymaster, recipient, priorityFee, maxFee };
}

async function runGood() {
  log('== GOOD case: paymaster pays gas, sender pays only the value ==');
  const { sender, paymaster, recipient, priorityFee, maxFee } = await common();
  const sBal0 = BigInt(await rpc('eth_getBalance', [sender.address, 'latest']));
  const pBal0 = BigInt(await rpc('eth_getBalance', [paymaster.address, 'latest']));
  const rBal0 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));

  const { payload, encode, sigHash } = buildEnvelope(sender.address, paymaster.address, recipient, 0n, priorityFee, maxFee, TRANSFER_VALUE);
  payload[4][0][3] = witnessSig(sender, sigHash);     // witness[0]: EXECUTION, signed by sender
  payload[4][1][3] = witnessSig(paymaster, sigHash);  // witness[1]: PAYMENT, signed by paymaster
  const raw = encode(payload);

  const hash = await rpc('eth_sendRawTransaction', [raw]);
  log('    tx', hash);
  const rc = await pollReceipt(hash);
  if (!rc) throw Error('GOOD tx produced no receipt');
  const frames = (rc.frameReceipts || []).map(f => f.status);
  log('    receipt status', rc.status, 'block', rc.blockNumber, 'gasUsed', rc.gasUsed, 'payer', rc.payer, 'frames', JSON.stringify(frames));
  if (BigInt(rc.status) !== 1n || frames.some(s => BigInt(s) !== 1n)) throw Error('GOOD tx did not fully succeed');

  const sBal1 = BigInt(await rpc('eth_getBalance', [sender.address, 'latest']));
  const pBal1 = BigInt(await rpc('eth_getBalance', [paymaster.address, 'latest']));
  const rBal1 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  const sDelta = sBal1 - sBal0, pDelta = pBal1 - pBal0, rDelta = rBal1 - rBal0;
  log('    sender delta   ', sDelta.toString(), '(expect -' + TRANSFER_VALUE + ', value only, no gas)');
  log('    paymaster delta', pDelta.toString(), '(expect negative = gas)');
  log('    recipient delta', rDelta.toString(), '(expect +' + TRANSFER_VALUE + ')');

  if ((rc.payer || '').toLowerCase() !== paymaster.address.toLowerCase()) throw Error('receipt.payer is not the paymaster');
  if (sDelta !== -TRANSFER_VALUE) throw Error('sender was charged gas (delta != -value)');
  if (pDelta >= 0n) throw Error('paymaster did not pay gas');
  if (rDelta !== TRANSFER_VALUE) throw Error('recipient did not receive the value');
  log('    GOOD ok: payer == paymaster, sender charged value only, recipient paid');
  return { hash, payer: rc.payer, sDelta, pDelta, rDelta };
}

async function runBad() {
  log('== BAD case: corrupted paymaster signature must be rejected, nobody charged ==');
  const { sender, paymaster, recipient, priorityFee, maxFee } = await common();
  const pBal0 = BigInt(await rpc('eth_getBalance', [paymaster.address, 'latest']));
  const rBal0 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));

  const { payload, encode, sigHash } = buildEnvelope(sender.address, paymaster.address, recipient, 0n, priorityFee, maxFee, TRANSFER_VALUE);
  payload[4][0][3] = witnessSig(sender, sigHash);
  // Corrupt the paymaster witness: flip one byte in the middle of its signature.
  const good = ethers.getBytes(witnessSig(paymaster, sigHash));
  good[Math.floor(good.length / 2)] ^= 0xff;
  payload[4][1][3] = ethers.hexlify(good);
  const raw = encode(payload);

  let submitError = null, hash = null;
  try { hash = await rpc('eth_sendRawTransaction', [raw]); }
  catch (err) { submitError = { code: err.rpcCode, message: err.message }; }

  if (submitError) {
    log('    REJECTED at admission:', JSON.stringify(submitError));
  } else {
    log('    gateway accepted structurally:', hash, '-> checking it never executes');
    const rc = await pollReceipt(hash, 20);
    if (rc && BigInt(rc.status) === 1n) throw Error('corrupted-signature tx was INCLUDED and succeeded: gate is broken');
    log('    no successful inclusion:', rc ? ('reverted status ' + rc.status) : 'no receipt');
  }
  const rBal1 = BigInt(await rpc('eth_getBalance', [recipient, 'latest']));
  const pBal1 = BigInt(await rpc('eth_getBalance', [paymaster.address, 'latest']));
  if (rBal1 !== rBal0) throw Error('recipient balance changed on a rejected tx');
  if (pBal1 !== pBal0) throw Error('paymaster was charged on a rejected tx');
  log('    BAD ok: recipient unchanged, paymaster not charged');
  return { outcome: submitError || { includedSuccessfully: false } };
}

async function main() {
  const chain = BigInt(await rpc('eth_chainId'));
  if (chain !== CHAIN_ID) throw Error(`RPC chainId ${chain} != expected ${CHAIN_ID}`);

  const good = await runGood();
  await runBad();

  log('');
  log('PoC daisugi paymaster GREEN on chain', CHAIN_ID.toString());
  log('  GOOD tx :', good.hash, 'https://explorer.daisugi.fyi/tx/' + good.hash);
  log('  payer   :', good.payer, '(the paymaster, not the sender)');
  log('  deltas  : sender', good.sDelta.toString(), '| paymaster', good.pDelta.toString(), '| recipient', good.rDelta.toString());
  log('  Proven: a third-party paymaster pays gas for a frame transaction via APPROVE(payment) in its own VERIFY frame (Gen1, ECDSA).');
}

main().catch(err => { console.error('FAILED:', err.message); process.exitCode = 1; });
