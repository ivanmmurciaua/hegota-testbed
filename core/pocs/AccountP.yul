// EIP-8141 post-quantum ACCOUNT for the frame-native PAYMASTER model (ethrex Hegota).
//
// Identical ML-DSA custody to pq-dksap's AccountF, with ONE change: this account's
// VERIFY frame approves EXECUTION ONLY (APPROVE opcode scope 2), never PAYMENT. The
// gas is approved by a SEPARATE Paymaster contract in its own VERIFY frame. So the
// account is the frame-tx sender (it orders and signs the action with ML-DSA) but it
// does NOT pay the gas.
//
// The ML-DSA verifier (SINGLETON) is a constructor arg (storage slot 1), so a Hegota
// re-genesis needs only a re-anchor, not a recompile. Constructor args appended to the
// init code: commit(32) || singleton(32, left-padded address).
//
// Expected frame layout (see poc_paymaster.py):
//   frame 0  VERIFY  (target = this account / sender)  -> APPROVE(0,0,2) execution only
//   frame 1  VERIFY  (target = Paymaster)              -> paymaster APPROVEs payment
//   frame 2  DEFAULT (target = this account) ATOMIC    -> heavy ML-DSA verify, revert-gated
//   frame 3  SENDER  (moves value)                     -> skipped if frame 2 reverts
// The account runs only at frames 0 and 2 (target is the sender in both). It tells them
// apart by the current frame index: index 0 = approve execution, else = ML-DSA verify.
//
// NOTE: Yul `verbatim` places the FIRST argument on TOP of the stack.
object "AccountP" {
    code {
        // constructor args appended: commit(32) || singleton(32), 64 bytes total
        codecopy(0, sub(codesize(), 64), 64)
        sstore(0, mload(0))    // slot 0 = key commitment
        sstore(1, mload(32))   // slot 1 = ML-DSA verifier (left-padded address word)
        let sz := datasize("runtime")
        datacopy(0, dataoffset("runtime"), sz)
        return(0, sz)
    }
    object "runtime" {
        code {
            let idx := verbatim_1i_1o(hex"b0", 0x0a)       // TXPARAM(current_frame_index)

            // Frame 0 (VERIFY): approve EXECUTION only. Execution approval requires the
            // approving frame's target to be the tx sender, which holds here (target is
            // the sender account). Payment is NOT approved: the Paymaster covers gas.
            if iszero(idx) {
                verbatim_3i_0o(hex"aa", 0, 0, 2)         // APPROVE(offset=0, length=0, scope=2=EXECUTION)
                stop()
            }

            // Otherwise (the DEFAULT frame): heavy ML-DSA verify, revert-gated by the
            // atomic batch so a bad signature skips the SENDER and funds do not move.
            let SINGLETON := sload(1)                    // verifier from constructor arg
            let PKLEN := 22400
            let SIGLEN := 2420

            let sigHash := verbatim_1i_1o(hex"b0", 0x08)   // TXPARAM(sig_hash)

            mstore(0, shl(224, 0xc34781db))          // verifyInline(bytes,bytes32,bytes) selector
            mstore(4, 0x60)                          // head: offset to pk
            mstore(36, sigHash)                      // head: m
            mstore(68, add(0x80, PKLEN))             // head: offset to sig
            mstore(100, PKLEN)                       // pk length
            verbatim_4i_0o(hex"b5", 132, 0, PKLEN, 0)          // SIGDATACOPY pk -> mem[132] (sig index 0)
            let sigLenPos := add(132, PKLEN)
            mstore(sigLenPos, SIGLEN)                // sig length
            let sigPos := add(sigLenPos, 32)
            verbatim_4i_0o(hex"b5", sigPos, PKLEN, SIGLEN, 0)  // SIGDATACOPY sig -> mem[sigPos] (sig index 0)
            let inLen := add(sigPos, 2432)           // SIGLEN padded to a 32-byte multiple

            // binding: the expanded public key must match this account's commitment
            if iszero(eq(keccak256(132, PKLEN), sload(0))) { revert(0, 0) }

            let ok := staticcall(gas(), SINGLETON, 0, inLen, inLen, 32)
            if iszero(ok) { revert(0, 0) }
            if iszero(eq(mload(inLen), shl(224, 0x024ad318))) { revert(0, 0) }
            stop()   // gate passed; the SENDER frame moves the value
        }
    }
}
