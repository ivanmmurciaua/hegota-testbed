// EIP-8141 frame-native PAYMASTER, simplest form (ethrex Hegota dialect).
//
// The 4337-style paymaster done natively in frames. The paymaster is NOT the tx sender
// (that is the account). It runs in its OWN VERIFY frame, as that frame's target, and
// approves PAYMENT (APPROVE opcode scope 1). ethrex then sets payer = frame.target with
// no payer==sender check, so this contract pays all the gas while the account (sender)
// pays only the value it deliberately moves.
//
// This is the unconditional "start simple" variant: it approves payment for any tx that
// names it. It reads NO storage, because VERIFY frames run in the validation prefix
// where a non-sender frame (the paymaster) may not SLOAD (ethrex rejects it as
// "StorageReadNonSender"). For an operator-gated paymaster that is still storage-free,
// see PaymasterGated.yul.tmpl (operator baked into code, ecrecover gate).
//
// A real paymaster would gate and meter; this one isolates the payer mechanism.
//
// NOTE: Yul `verbatim` places the FIRST argument on TOP of the stack.
object "Paymaster" {
    code {
        let sz := datasize("runtime")
        datacopy(0, dataoffset("runtime"), sz)
        return(0, sz)
    }
    object "runtime" {
        code {
            verbatim_3i_0o(hex"aa", 0, 0, 1)   // APPROVE(offset=0, length=0, scope=1=PAYMENT)
            stop()
        }
    }
}
