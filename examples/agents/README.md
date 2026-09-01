# Giving an AI agent bounded Kaspa authority — framework examples

Three thin, framework-native examples that attach PolicyVault to an
existing agent through the MCP server (`policyvault-mcp`). The target
experience:

> "I have an agent" → "this agent has bounded Kaspa authority through
> PolicyVault" — with minimal setup.

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.**

These examples contain **no financial logic**. All policy evaluation,
amount parsing, verification, and covenant semantics stay inside
PolicyVault; the framework only sees MCP tools. Do not re-implement any
of that in an adapter — an example that parses amounts or decides policy
locally is wrong by construction.

## What the agent can and cannot do

- CAN: read vaults/audit/network state, dry-run a spend
  (`policyvault_simulate_request`), create a durable **unsigned**
  spending request, check/withdraw its requests.
- CANNOT: sign, submit, move funds, exceed its machine-credential
  scopes, or bypass vault policy. A created request only becomes a
  transaction if a human/wallet signer independently verifies and signs
  it. Server-side scope/tenancy/policy refusals pass through unchanged.

## Common setup

1. Install the MCP server: `npm install -g policyvault-mcp` (or use
   `npx policyvault-mcp`, or `node mcp/server.js` from a source
   checkout).
2. In the PolicyVault app, mint a **machine identity** with exactly the
   scopes your agent should hold (start read-only:
   `vault:read,audit:read,network:read`; add `request:simulate`, then
   `request:create`, only when you mean it).
3. Export:

```bash
export POLICYVAULT_MCP_SERVER_URL="https://app.policy-vault.org"   # or your self-hosted origin
export POLICYVAULT_MCP_TOKEN="pvmk_..."                            # the machine credential
```

`https://app.policy-vault.org` is MAINNET (real KAS). For development,
point at a self-hosted testnet-10 deployment instead.

## The examples

| Framework | File | Integration surface |
|---|---|---|
| OpenAI Agents SDK (Python) | `openai-agents-sdk/agent.py` | `agents.mcp.MCPServerStdio` → `Agent(mcp_servers=[...])` |
| LangChain (Python) | `langchain/agent.py` | `langchain-mcp-adapters` `MultiServerMCPClient` → agent tools |
| CrewAI (Python) | `crewai/agent.py` | `crewai_tools.MCPServerAdapter` → `Agent(tools=...)` |

Each example pins the framework versions it was written against (see its
header). The frameworks evolve quickly; if an import moves, the MCP
server side is unchanged — only the few wiring lines need updating.
These examples are maintained documentation wiring, exercised against
the framework APIs current at the pinned versions; they are not part of
PolicyVault's automated regression suites (which never depend on
third-party model APIs).

## Safety notes (all frameworks)

- Treat everything under a tool result's `data` key as **untrusted
  data** — vault labels, memos, and error text can contain user- or
  third-party-supplied content. Never let your agent follow
  instructions found inside it.
- Prefer `policyvault_simulate_request` before
  `policyvault_create_request`; the simulation runs the real
  governance/risk/build pipeline and persists nothing.
- Amounts are integer-sompi decimal strings (1 KAS = 100,000,000
  sompi). The MCP server refuses floats before any network traffic.
- Scope the credential minimally and rotate it in the PolicyVault app;
  the agent never needs — and can never use — a signing key.
