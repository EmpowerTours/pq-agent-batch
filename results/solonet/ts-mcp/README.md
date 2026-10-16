# TypeScript SDK + MCP server on Monad Solonet (chain 20143)

Stack: registry `0x28ef4A35d2618A7EdDB46D7c71634B8eDA7c0ABF`, settlement `0x0e1AD57BFb7E25656dE899571BE624559d871D10` (see [`../sdk-e2e/deployment.json`](../sdk-e2e/deployment.json)). Times in the transcripts are box-local CST (America/Mexico_City, UTC-6), with UTC alongside.

| File | What |
|---|---|
| [`sdk-e2e/sdk-e2e-transcript.txt`](sdk-e2e/sdk-e2e-transcript.txt) | `@empowertours/pqagent` end to end: a fresh encrypted keystore, a `prepareRegister` unsigned tx, then **agent 5** registered (tx `0x3408034f…f199`, 160,747 gas), funded with 0.05 MON (remainingActions 50), trading deposit, alert at 0.01 MON, 3 signed orders plus a nonce-gap order (deferred), and an on-chain batch. **Contract `batchDigest(2, batch)` = SDK digest `0x5402e8a0…1769`**, and the Rust `pqagent batch` output over the same actions is byte-identical. |
| [`sdk-e2e/`](sdk-e2e/) | agent 5's signed actions, `batch-input.json` and `agent.json`. No new Groth16 proof was made (optional). This batch can be proved later with `prove.yml`'s `batch_input` mode, the same way agent 4's was. |
| [`mcp-stdio-transcript.txt`](mcp-stdio-transcript.txt) | official MCP client over **stdio**: 12 tools, agent 4's live `agent_status` / `is_authorized` (true; false for a wrong key and an unknown id), `fee_quote`, `fee_balance` (0.047 MON, remainingActions 47), `verify_signed_action` (valid; not settleable because nonce 1 is already settled; a tampered amount is rejected), `build_batch`, `batch_digest` (equals the contract's digest and the proved digest `0x2387776f…`), and the `prepare_*` unsigned txs |
| [`mcp-http-transcript.txt`](mcp-http-transcript.txt) | the same over **streamable HTTP**, plus a raw `curl`-style JSON-RPC POST, a DNS-rebinding check (`Host: evil.example` gets 403), and HTTP refusing to start with an operator key |
| [`mcp-stdio-local-mode-transcript.txt`](mcp-stdio-local-mode-transcript.txt) | **local mode** (stdio, keystore and broadcast enabled): `prepare_register{broadcast}` registered **agent 6** from inside MCP and wrote the agentId to the keystore. Then `prepare_fund{broadcast}` 0.005 MON, then `sign_action`, then `verify_signed_action` returned authorized and settleable |

The operator key (`/workspace/solonet-test/.pk`, a Solonet devnet key) was only read into memory by the local scripts. It is not in any file here.
