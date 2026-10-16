# pqagent MCP server

An [MCP](https://modelcontextprotocol.io) server for the pq-agent-batch proof-of-agency registry. Any AI client, such as Claude, Cursor, VS Code Copilot, ChatGPT or Grok Bot, can use it to **check whether an agent is authorized, verify its post-quantum signed actions, and register or fund an agent in one step**. It needs no API key. It is built on the official `@modelcontextprotocol/sdk` and the [TypeScript SDK](../sdk-ts/README.md), and supports **stdio** and **streamable HTTP**.

```bash
npm ci && npm run build                     # repo root
node mcp/dist/cli.js                        # stdio
node mcp/dist/cli.js --http --port 3333     # streamable HTTP on http://127.0.0.1:3333/mcp (stateless, JSON responses)
```

## Tools

| Tool | Kind | What it does |
|---|---|---|
| `network_info` | read | chain, registry/settlement addresses, open registration, registration fee, min bond, max caps, agent count, fee per action, SP1 vkey |
| `agent_status` | read | operator, active/killed, bond, caps, key count, lastNonce/nextNonce, fee balance, remainingActions, trading balances; `authorized` if `pkHash` is given |
| `is_authorized` | read | `AgentRegistry.isAuthorized(agentId, pkHash)` plus the reason when false (unknown / killed / retired / not a current key) |
| `fee_quote` | read | `feeQuote(agentId, actions)` and whether the prepaid balance covers it |
| `fee_balance` | read | prepaid fee account: balance, token, fee per action, **remainingActions**, alert threshold, `low`, auto top-up, pending withdrawal, top-up advice |
| `verify_signed_action` | read | full ML-DSA-65 check of a v1 signed action (schema, pkHash, 133-byte message, signature) plus on-chain authorized / nonce fresh / not expired → `settleable` |
| `batch_digest` | read | digest of a packed batch (equal to the contract's `batchDigest` and the proof's public values), decoded groups and orders, compared with the contract |
| `build_batch` | read | reference batcher over signed actions: the prover input plus every excluded action with its reason |
| `prepare_register` | unsigned tx | `selfRegister(pkHash, caps)` with `value = registrationFee + bond` |
| `prepare_fund` | unsigned tx | prepaid fee deposit (`depositFeeNative`, or approve + `depositFeeToken`) |
| `prepare_deposit` | unsigned tx | trading balances (approve + `deposit`) |
| `prepare_set_alert` | unsigned tx | `setFeeAlert` (+ `setAutoTopUp`) → `LowFeeBalance` event when the balance runs low |
| `local_agent` | local only | the local keystore's agentId / pkHash / modelHash / nonce / authorized. Never returns key material |
| `sign_action` | local only | ML-DSA-65 signs an order with the local keystore and returns (and optionally writes) the v1 JSON |

**Keys never live on a server.** The `prepare_*` tools return `{ chainId, to, data, value }` for the operator's own wallet to sign. There is one exception, and it is off by default. In **local stdio mode**, `PQAGENT_MCP_ENABLE_SEND=1` together with `PQAGENT_OPERATOR_KEY_FILE` (or `PQAGENT_OPERATOR_KEY`) adds a `broadcast: true` option to the `prepare_*` tools, so the server sends them itself. In that mode `prepare_register` with no pkHash registers the local keystore and records the new agentId. The server **refuses to start** if `PQAGENT_MCP_ENABLE_SEND` is set with `--http`. `sign_action` and `local_agent` exist only in stdio mode, and only when `PQAGENT_DIR` points to a keystore (passphrase in `PQAGENT_PASSPHRASE`).

## Configuration (env)

| Var | Default |
|---|---|
| `PQAGENT_RPC` | `http://localhost:8080` (Monad Solonet) |
| `PQAGENT_CHAIN_ID` | `20143` |
| `PQAGENT_SETTLEMENT` | `0x0e1AD57BFb7E25656dE899571BE624559d871D10` |
| `PQAGENT_REGISTRY` | `0x28ef4A35d2618A7EdDB46D7c71634B8eDA7c0ABF` (or `settlement.registry()` when `PQAGENT_SETTLEMENT` is set) |
| `PQAGENT_NETWORK_NAME` | derived from the chain id |
| `PQAGENT_DIR`, `PQAGENT_PASSPHRASE` | local stdio only: keystore for `sign_action` |
| `PQAGENT_MCP_ENABLE_SEND`, `PQAGENT_OPERATOR_KEY_FILE` / `PQAGENT_OPERATOR_KEY` | local stdio only, off by default: broadcast prepared txs |

The RPC URL is shown to clients without its path, query or credentials, because API keys often live there. All logs go to stderr.

## Client setup

Replace `/ABS/PATH` with the path to your checkout. These examples point at a local Solonet. For another deployment, set the `PQAGENT_*` vars.

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "pqagent": {
      "command": "node",
      "args": ["/ABS/PATH/pq-agent-batch/mcp/dist/cli.js"],
      "env": { "PQAGENT_RPC": "http://localhost:8080" }
    }
  }
}
```

**Claude Code**:
```bash
claude mcp add pqagent --env PQAGENT_RPC=http://localhost:8080 -- node /ABS/PATH/pq-agent-batch/mcp/dist/cli.js
# or, with the HTTP server running:
claude mcp add --transport http pqagent http://127.0.0.1:3333/mcp
```

**Cursor** (`~/.cursor/mcp.json` or `.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "pqagent": { "command": "node", "args": ["/ABS/PATH/pq-agent-batch/mcp/dist/cli.js"], "env": { "PQAGENT_RPC": "http://localhost:8080" } }
  }
}
```
For HTTP, use `"pqagent": { "url": "http://127.0.0.1:3333/mcp" }`.

**VS Code** (`.vscode/mcp.json`):
```json
{
  "servers": {
    "pqagent": { "type": "stdio", "command": "node", "args": ["/ABS/PATH/pq-agent-batch/mcp/dist/cli.js"], "env": { "PQAGENT_RPC": "http://localhost:8080" } }
  }
}
```
For HTTP, use `"pqagent": { "type": "http", "url": "http://127.0.0.1:3333/mcp" }`.

**Local signing agent** (stdio only; registers, funds and signs from the chat, so the AI should confirm with you before each one):
```json
"env": { "PQAGENT_DIR": "/ABS/PATH/.pqagent", "PQAGENT_PASSPHRASE": "…", "PQAGENT_MCP_ENABLE_SEND": "1", "PQAGENT_OPERATOR_KEY_FILE": "/ABS/PATH/op.key" }
```

**Any HTTP client** (stateless: no session, no initialize needed for a single call):
```bash
curl -s http://127.0.0.1:3333/mcp -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"is_authorized","arguments":{"agentId":4,"pkHash":"0x7c2c8a8b98c34df4a50204357e33cdd8155a64be11ac2fcd2c7b395d13271602"}}}'
```
The MCP Inspector also works: `npx @modelcontextprotocol/inspector node mcp/dist/cli.js`.

## Tests

- `npm test -w mcp`: in-memory client tests that need no chain. They check the tool list and hints, reproduce the proved N=10 digest, verify a proved-batch signature, reject tampering, check that the server fails closed on operator keys, and check RPC redaction.
- `mcp/scripts/smoke.ts`: the official MCP client over **stdio and streamable HTTP** against a live chain. It also sends a raw JSON-RPC POST, checks DNS-rebinding protection (a bad `Host` gets 403), checks that HTTP refuses an operator key, and with `LOCAL_MODE=1` runs register → fund → sign → verify from inside MCP.
- `mcp/scripts/anvil-ci.sh`: the CI job. It deploys to anvil, runs the TS SDK end to end, then runs the MCP smoke test.
- Live Solonet transcripts: [`results/solonet/ts-mcp/`](../results/solonet/ts-mcp/).

## Hosting a public endpoint (like zambo.dev/mcp): not deployed, needs a decision first

The HTTP mode is designed to be safe to expose: read-only and unsigned-tx tools only, stateless, no keys, a 4 MB body limit and a Host allow-list. To run it publicly you would still need:

1. **A public chain to point at.** Solonet is a localhost devnet. Deploy the registry and settlement to Monad testnet (or mainnet after an audit) and set `PQAGENT_CHAIN_ID`, `PQAGENT_RPC`, `PQAGENT_SETTLEMENT` and `PQAGENT_REGISTRY`.
2. **An RPC with headroom.** Every tool call makes 1 to 8 `eth_call`s. Use a provider key kept server-side (the URL is already redacted in output), and add caching if traffic grows.
3. **TLS and a hostname.** Run `pqagent-mcp --http --host 0.0.0.0 --allowed-hosts mcp.example.com` behind a TLS reverse proxy (Caddy or nginx), or on a host that provides TLS, such as Fly.io, Render, Railway or a small VPS. The SDK's web-standard transport would also allow a Cloudflare Workers port.
4. **Abuse controls that are not built in yet:** per-IP rate limiting, request timeouts on the RPC, and logging and metrics. If it is ever monetized, add optional API keys or x402-style payments.
5. **Never set `PQAGENT_MCP_ENABLE_SEND` there.** The server refuses to start that way.
