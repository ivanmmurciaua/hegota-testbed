// Gen1 in-frame SPHINCS account: our own runtime + clone-factory generators.
//
// Daisugi (Nethermind) native frame opcodes are NOT standard EVM; Solidity cannot
// emit them. This module AUTHORS the account verification runtime from the documented
// opcode semantics (it does not copy the reference library source). The emitted
// program, for APPROVE scope 3, is byte-identical to the pinned reference impl on
// chain, which is asserted at runtime by the PoC (eth_getCode comparison) before use.
//
// Native opcode reference (node pinned, not standard EVM):
//   0xb0 TXPARAM(field)                 2=tx sender, 8=signing digest,
//                                        0x0a=current frame index, 0x0b=witness count
//   0xb3 FRAMEPARAM(index, field)       field 2=mode
//   0xb4 WITNESSPARAM(field, witIndex)  field 1=scheme, 2=msg len, 3=sig len
//   0xb5 SIGDATACOPY                    copies the current frame's witness signature
//   0xaa APPROVE(scope)                 1=PAYMENT, 2=EXECUTION, 3=both (terminating)
// ecrecover is the standard precompile 0x01.

// SPHINCS-G verifier, LIVE on Daisugi (reuse, do not deploy):
export const SPHINCS_VERIFIER = '0xf505AD2Cff58b84E145D637d99Fae0617B5685BE';
export const SPHINCS_SIG_BYTES = 6176;
// verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 digest, bytes sig) -> 32-byte word == 1
const VERIFY_SELECTOR = '2bf6eda8';
// Total verify() calldata size: selector + 3 words + offset + length + 6176-byte sig.
const VERIFY_CALLDATA_SIZE = 4 + 32 * 5 + SPHINCS_SIG_BYTES; // 6340

// A tiny labelled assembler for the pinned native dialect. Mirrors the documented
// helper shapes (minimal PUSH, two-byte jump targets) so the output is deterministic.
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
    op(0x61); // PUSH2 placeholder, patched once labels are known
    jumps.push({ label, offset: code.length });
    code.push(0, 0);
    op(conditional ? 0x57 : 0x56);
  };
  const label = name => { labels.set(name, code.length); op(0x5b); };
  const requireTrue = () => { op(0x15); jump('reject'); }; // assert top is nonzero
  const tx = field => { push(field); op(0xb0); };          // TXPARAM(field)
  const sig = field => { push(field); push(0); op(0xb4); }; // WITNESSPARAM(field, 0)
  const store = (value, offset) => { push(value); push(offset); op(0x52); }; // MSTORE
  const finalize = () => {
    for (const { label: name, offset } of jumps) {
      const dest = labels.get(name);
      if (dest === undefined || dest > 65535) throw Error('invalid jump target');
      code[offset] = dest >> 8;
      code[offset + 1] = dest & 0xff;
    }
    return '0x' + Buffer.from(code).toString('hex');
  };
  return { op, push, jump, label, requireTrue, tx, sig, store, finalize };
}

// Build the account verification runtime. `scope` is the APPROVE scope this account
// grants once its SPHINCS signature verifies: 3 = execution + payment (self-pay),
// 2 = execution only (a paymaster then approves payment in its own frame).
//
// `soleWitness` keeps the reference self-pay hardening that the transaction carry
// exactly one witness (TXPARAM 0x0b == 1). That is correct for self-pay but is wrong
// for a sponsored account: a paymaster adds a second VERIFY frame and therefore a
// second witness, so the execution-only variant must NOT require the sole witness.
// With scope 3 and soleWitness true this emits the pinned reference impl byte-for-byte.
export function buildAccountRuntime(scope, verifier = SPHINCS_VERIFIER, { soleWitness = true } = {}) {
  if (![1, 2, 3].includes(scope)) throw Error('scope must be 1, 2 or 3');
  const a = assembler();

  // Native frame entry arrives with CALLER == 0xaa (the node sentinel). Any other
  // caller is an ordinary transfer: it may fund the account (empty calldata) but can
  // never approve frame execution.
  a.op(0x33); a.push(0xaa); a.op(0x14); a.jump('verify');  // if CALLER==0xaa goto verify
  a.op(0x36); a.op(0x15); a.requireTrue(); a.op(0x00);     // else require empty calldata, STOP

  a.label('verify');
  a.op(0x36); a.op(0x15); a.requireTrue();                 // no owner suffix: calldata empty
  a.tx(2); a.op(0x30); a.op(0x14); a.requireTrue();        // tx sender == this account
  a.op(0x30); a.op(0x3b); a.push(109); a.op(0x14); a.requireTrue(); // EXTCODESIZE == 109
  a.push(2); a.tx(0x0a); a.op(0xb3); a.push(1); a.op(0x14); a.requireTrue(); // current frame mode == VERIFY
  if (soleWitness) { a.tx(0x0b); a.push(1); a.op(0x14); a.requireTrue(); }   // exactly one witness (self-pay only)
  a.sig(1); a.push(0); a.op(0x14); a.requireTrue();        // witness scheme == 0 (ARBITRARY)
  a.sig(2); a.push(0); a.op(0x14); a.requireTrue();        // witness msg length == 0
  a.sig(3); a.push(SPHINCS_SIG_BYTES); a.op(0x14); a.requireTrue(); // witness sig length == 6176

  // Assemble verify(bytes32,bytes32,bytes32,bytes) calldata in memory.
  a.store(VERIFY_SELECTOR + '00'.repeat(28), 0);           // [0:4] selector
  // DELEGATECALL keeps ADDRESS as the clone, so read the clone's immutable public key
  // straight from its own code: EXTCODECOPY(self, dest=4, codeOffset=45, size=64).
  a.push(64); a.push(45); a.push(4); a.op(0x30); a.op(0x3c);   // [4:68] pkSeed||pkRoot
  a.tx(8); a.push(68); a.op(0x52);                          // [68:100] signing digest
  a.store(128, 100);                                        // [100:132] bytes offset 0x80
  a.store(SPHINCS_SIG_BYTES, 132);                          // [132:164] bytes length
  a.push(0); a.push(SPHINCS_SIG_BYTES); a.push(0); a.push(164); a.op(0xb5); // SIGDATACOPY -> [164:]
  a.push(32); a.push(0); a.push(VERIFY_CALLDATA_SIZE); a.push(0);
  a.push(verifier.replace(/^0x/, '').toLowerCase());        // PUSH20 verifier address
  a.op(0x5a); a.op(0xfa);                                   // GAS, STATICCALL
  a.requireTrue(); a.op(0x3d); a.push(32); a.op(0x14); a.requireTrue(); // ok and returndatasize == 32
  a.push(0); a.op(0x51); a.push(1); a.op(0x14); a.requireTrue();        // returned word == 1

  a.push(scope); a.push(0); a.push(0); a.op(0xaa);          // APPROVE(scope), terminating
  a.label('reject'); a.push(0); a.push(0); a.op(0xfd);      // REVERT(0,0)
  return a.finalize();
}

// Build a k1 paymaster runtime (a plain contract, not a clone). In its VERIFY frame
// (flags 1 = PAYMENT) it recovers a secp256k1 operator signature carried in its
// ARBITRARY witness, requires the recovered address to equal a baked-in operator
// constant (storage-free), then APPROVEs payment. The witness signature is 65 bytes
// r(32) || s(32) || v(1), with v == 27 or 28.
//
// `witnessSlot` is the SIGDATACOPY witness index (its first/deepest operand). Verified
// on Daisugi to be the ABSOLUTE witness index, not the current frame: witness i pairs
// with the i-th VERIFY frame (execution-approving verify -> 0, payment-approving verify
// -> 1, matching the node's default-code sigIndex rule). A paymaster at the second
// VERIFY frame therefore reads slot 1; the account at the first reads slot 0.
export function buildPaymasterRuntime(operator, witnessSlot = 1) {
  const op20 = operator.replace(/^0x/, '').toLowerCase();
  if (op20.length !== 40) throw Error('bad operator address');
  const a = assembler();

  // Native frame entry arrives with CALLER == 0xaa. Any other caller may only fund
  // the paymaster (empty calldata); it can never approve payment.
  a.op(0x33); a.push(0xaa); a.op(0x14); a.jump('verify');
  a.op(0x36); a.op(0x15); a.requireTrue(); a.op(0x00);

  a.label('verify');
  a.op(0x36); a.op(0x15); a.requireTrue();                 // empty calldata (no suffix)
  a.push(2); a.tx(0x0a); a.op(0xb3); a.push(1); a.op(0x14); a.requireTrue(); // current frame mode == VERIFY

  // Assemble the 128-byte ecrecover input in memory:
  //   [0:32] hash = canonical signing digest (TXPARAM 8)
  //   [32:64] v   [64:96] r   [96:128] s
  a.tx(8); a.push(0); a.op(0x52);                          // mem[0:32] = digest
  // SIGDATACOPY the 65-byte witness sig to mem[64:129]: r@64, s@96, v byte @128.
  a.push(witnessSlot); a.push(65); a.push(0); a.push(64); a.op(0xb5);
  a.push(128); a.op(0x51); a.push(248); a.op(0x1c);        // v = mem[128] >> 248 (isolate the v byte)
  a.push(32); a.op(0x52);                                  // mem[32:64] = v
  // ecrecover precompile 0x01: staticcall(gas, 1, in=0:128, out=0:32).
  a.push(32); a.push(0); a.push(128); a.push(0); a.push(1); a.op(0x5a); a.op(0xfa);
  a.requireTrue(); a.op(0x3d); a.push(32); a.op(0x14); a.requireTrue(); // ok and 32-byte return
  a.push(0); a.op(0x51);                                   // recovered address word
  a.push(op20); a.op(0x14); a.requireTrue();               // == baked-in operator

  a.push(1); a.push(0); a.push(0); a.op(0xaa);             // APPROVE(payment), terminating
  a.label('reject'); a.push(0); a.push(0); a.op(0xfd);
  return a.finalize();
}

// Wrap any runtime in a minimal constructor that returns it verbatim.
export function deployInitCode(runtimeHex) {
  const runtime = runtimeHex.replace(/^0x/, '');
  const len = runtime.length / 2;
  const lenHex = len.toString(16).padStart(4, '0');
  // PUSH2 len, PUSH1 14 (prefix size), PUSH1 0, CODECOPY, PUSH2 len, PUSH1 0, RETURN
  const prefix = `61${lenHex}600e600039` + `61${lenHex}6000f3`;
  return '0x' + prefix + runtime;
}

// EIP-1167 clone runtime for a given account impl and SPHINCS public key.
// Layout: 363d3d373d3d3d363d73 || impl(20) || 5af43d82803e903d91602b57fd5bf3 || pkSeed(32) || pkRoot(32).
export function cloneRuntime(impl, pkSeedWord, pkRootWord) {
  const i = impl.replace(/^0x/, '').toLowerCase();
  if (i.length !== 40) throw Error('bad impl address');
  for (const w of [pkSeedWord, pkRootWord]) {
    if (!/^0x[0-9a-f]{32}0{32}$/i.test(w)) throw Error('public key must be 16 meaningful bytes, left-aligned in a word');
  }
  return '0x363d3d373d3d3d363d73' + i + '5af43d82803e903d91602b57fd5bf3' +
    pkSeedWord.slice(2) + pkRootWord.slice(2);
}

// Pad a 16-byte SPHINCS public-key half ("0x" + 32 hex) into a left-aligned 32-byte word.
export function pkWord(half) {
  const h = half.replace(/^0x/, '').toLowerCase();
  if (h.length !== 32) throw Error('expected a 16-byte public-key half');
  return '0x' + h + '0'.repeat(32);
}

// Build the Yul source for our CREATE2 clone factory, with the impl baked in.
// createAccount(bytes32 pkSeed, bytes32 pkRoot, bytes32 salt) -> address.
export function factoryYul(impl) {
  const i = impl.replace(/^0x/, '').toLowerCase();
  if (i.length !== 40) throw Error('bad impl address');
  // Clone init code (119 bytes): 3d606d80600a3d3981f3 (CREATE2 wrapper, returns 109)
  //   || 363d3d373d3d3d363d73 || impl(20) || 5af43d82803e903d91602b57fd5bf3 || pkSeed(32) || pkRoot(32)
  const fixed55 = '3d606d80600a3d3981f3' + '363d3d373d3d3d363d73' + i + '5af43d82803e903d91602b57fd5bf3';
  // 55 bytes = 110 hex. Split into word A [0:32] and word B [32:55] right-padded to a word.
  const wordA = fixed55.slice(0, 64);
  const wordB = fixed55.slice(64).padEnd(64, '0'); // [32:55] then zero placeholder overwritten by pkSeed
  return `object "AccountFactory" {
  code {
    datacopy(0, dataoffset("runtime"), datasize("runtime"))
    return(0, datasize("runtime"))
  }
  object "runtime" {
    code {
      let pkSeed := calldataload(4)
      let pkRoot := calldataload(36)
      let salt := calldataload(68)
      mstore(0, 0x${wordA})
      mstore(32, 0x${wordB})
      mstore(55, pkSeed)
      mstore(87, pkRoot)
      let account := create2(0, 0, 119, salt)
      if iszero(account) { revert(0, 0) }
      mstore(0, account)
      return(0, 32)
    }
  }
}
`;
}
