// Sponsor-route PQ smart account for the live Hegota build (3151908).
//
// Runs as a DEFAULT frame (post-prefix, uncapped) so the ~5-8M-gas ML-DSA verify
// fits (the public node's MAX_VERIFY_GAS only caps the VERIFY prefix). A sponsor EOA
// is the frame-tx sender and pays: the recognized prefix VERIFY(sender,0x3) + its k1
// signature approves execution+payment. This account's DEFAULT frame then verifies
// the inline ML-DSA signature over the tx sig_hash and executes an arbitrary call AS
// itself. sig_hash commits to this frame's calldata, so the PQ signature authorizes
// exactly (target, value, data).
//
// Constructor args appended: commit(32) || singleton(32, verifier address).
// The ML-DSA pk||sig travel in ARBITRARY signature index 1 (index 0 is the sponsor's
// secp256k1). Frame calldata layout: to(32, left-padded) || value(32) || innerData.
//
// NOTE: Yul `verbatim` places the FIRST argument on TOP of the stack.
object "PQExecAccount" {
    code {
        codecopy(0, sub(codesize(), 64), 64)
        sstore(0, mload(0))    // key commitment
        sstore(1, mload(32))   // ML-DSA verifier (SINGLETON)
        let sz := datasize("runtime")
        datacopy(0, dataoffset("runtime"), sz)
        return(0, sz)
    }
    object "runtime" {
        code {
            let PKLEN := 22400
            let SIGLEN := 2420
            let SINGLETON := sload(1)
            let sigHash := verbatim_1i_1o(hex"b0", 0x08)   // TXPARAM(sig_hash)

            // Build verifyInline(pk, sigHash, sig) input at mem[0..].
            mstore(0, shl(224, 0xc34781db))
            mstore(4, 0x60)
            mstore(36, sigHash)
            mstore(68, add(0x80, PKLEN))
            mstore(100, PKLEN)
            verbatim_4i_0o(hex"b5", 132, 0, PKLEN, 1)          // SIGDATACOPY pk  <- sig idx 1
            let sigLenPos := add(132, PKLEN)
            mstore(sigLenPos, SIGLEN)
            let sigPos := add(sigLenPos, 32)
            verbatim_4i_0o(hex"b5", sigPos, PKLEN, SIGLEN, 1)  // SIGDATACOPY sig <- sig idx 1
            let inLen := add(sigPos, 2432)

            if iszero(eq(keccak256(132, PKLEN), sload(0))) { revert(0, 0) }
            let ok := staticcall(gas(), SINGLETON, 0, inLen, inLen, 32)
            if iszero(ok) { revert(0, 0) }
            if iszero(eq(mload(inLen), shl(224, 0x024ad318))) { revert(0, 0) }

            // Gate passed. Execute the call: calldata = to(32) || value(32) || inner.
            let to := and(calldataload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            let val := calldataload(32)
            let ilen := sub(calldatasize(), 64)
            let iptr := add(inLen, 32)
            calldatacopy(iptr, 64, ilen)
            let success := call(gas(), to, val, iptr, ilen, 0, 0)
            if iszero(success) { revert(0, 0) }
            stop()
        }
    }
}
