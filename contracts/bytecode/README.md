# SP1 v6.1.0 Groth16 verifier bytecode

`sp1-verifier-groth16-v6.1.0.init.hex` is a 12-byte deployer (`PUSH2 len; DUP1; PUSH1 0x0c; PUSH1 0; CODECOPY; PUSH1 0; RETURN`) followed by the runtime bytecode of Succinct's `SP1VerifierGroth16` v6.1.0 (`VERSION() = "v6.1.0"`, `VERIFIER_HASH() = 0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696`).

The runtime is byte-identical to the deployed verifier on Monad mainnet (chain 143) at `0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2`, which is `V6_1_0_SP1_VERIFIER_GROTH16` in [succinctlabs/sp1-contracts `contracts/deployments/143.json`](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/deployments/143.json). Source: [`contracts/src/v6.1.0/SP1VerifierGroth16.sol`](https://github.com/succinctlabs/sp1-contracts/tree/v6.1.0/contracts/src/v6.1.0) (MIT).

Check it yourself:

```bash
[ "$(cast code 0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2 --rpc-url https://rpc.monad.xyz)" = \
  "$(sed 's/^0x611a5580600c6000396000f3/0x/' contracts/bytecode/sp1-verifier-groth16-v6.1.0.init.hex)" ] && echo identical
```

Used by `script/DeploySolonet.s.sol` (deploys the verifier on a devnet) and `test/RealGroth16Settle.t.sol` (verifies the committed real proofs in CI).
