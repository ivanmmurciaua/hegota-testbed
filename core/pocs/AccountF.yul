// EIP-8141 post-quantum self-paying ACCOUNT (Hegota), PoC-F' variant.
//
// Same shape as pq-dksap's Account.yul, with:
//   1. The ML-DSA verifier (SINGLETON) is a CONSTRUCTOR ARG (storage slot 1), not a
//      hardcoded literal, so a Hegota re-genesis (which wipes/redeploys the verifier)
//      needs only a re-anchor, never a recompile. Constructor args appended to the
//      init code: commit(32) || singleton(32, left-padded address).
//   2. The spend frame tx batches DEFAULT(verify) + SENDER(value) with FLAG_ATOMIC_BATCH,
//      so a failed ML-DSA verify SKIPS the SENDER and the funds do not move (hard gate
//      with self-pay; see finding1-resuelto-atomic-batch).
//
// The account is the tx sender and pays its own gas. The public key travels inline in
// the ARBITRARY signature; keccak256(expanded pk) must equal the stored commit.
//
// NOTE: Yul `verbatim` places the FIRST argument on TOP of the stack.
object "AccountF" {
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
            let nframes := verbatim_1i_1o(hex"b0", 0x09)   // TXPARAM(frame count)
            let idx := verbatim_1i_1o(hex"b0", 0x0a)       // TXPARAM(current_frame_index)

            // VERIFY frame (3rd from last): approve execution + payment, cheaply.
            if eq(idx, sub(nframes, 3)) {
                verbatim_3i_0o(hex"aa", 0, 0, 3)         // APPROVE(offset=0, length=0, scope=3)
                stop()
            }

            // DEFAULT frame (2nd from last): heavy ML-DSA verify, revert-gated.
            let SINGLETON := sload(1)                    // verifier from constructor arg
            let PKLEN := 22400
            let SIGLEN := 2420

            let sigHash := verbatim_1i_1o(hex"b0", 0x08)   // TXPARAM(sig_hash)

            mstore(0, shl(224, 0xc34781db))          // verifyInline(bytes,bytes32,bytes) selector
            mstore(4, 0x60)                          // head: offset to pk
            mstore(36, sigHash)                      // head: m
            mstore(68, add(0x80, PKLEN))             // head: offset to sig
            mstore(100, PKLEN)                       // pk length
            verbatim_4i_0o(hex"b5", 132, 0, PKLEN, 0)          // SIGDATACOPY pk -> mem[132]
            let sigLenPos := add(132, PKLEN)
            mstore(sigLenPos, SIGLEN)                // sig length
            let sigPos := add(sigLenPos, 32)
            verbatim_4i_0o(hex"b5", sigPos, PKLEN, SIGLEN, 0)  // SIGDATACOPY sig -> mem[sigPos]
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
