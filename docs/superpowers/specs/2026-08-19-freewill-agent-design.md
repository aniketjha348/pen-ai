# Freewill Agent — LLM-First Self-Driving Pentest Agent (Design)

Date: 2026-08-19
Branch: `enterprise-hardening` (working)

## Problem

The current `MasterAgent` treats the LLM as a menu-picker: `Planner` and `Reasoner`
generate a fixed set of hardcoded candidate actions and the LLM only chooses among
them. The user wants the coding-agent experience (Claude Code / opencode / Codex):

- Say "start" → the agent just starts doing the work.
- Full shell freedom — run any command, install missing tools, retry, adapt.
- No fixed attack chain or scripted menu.
- Cyber-focused alignment so it reasons like a pentester and does not hallucinate.

## Solution

A new module `ai/freewill_agent.py`: an LLM-first, self-driving agent loop that uses
real OpenAI-style tool calling (schemas, not string parsing), the full registered
tool registry, and a scope-validated shell tool as its primary instrument.

## Architecture

```
FreewillAgent
├── LLMClient (chat_raw + tool schemas)        — decision maker
├── ToolRegistry (registered pentest tools)    — structured evidence tools
├── ShellTool (scope-validated bash)           — opencode-style primary tool
├── FileTools (read/write/list)                — local attacker-box files
├── ScopeValidator (ROE)                       — guardrail on every command
├── FlagScanner (regex on outputs)             — CTF/flag termination
├── StateTracker (hosts/services/creds/findings) — accumulated knowledge
├── EvidenceCollector                          — evidence for report
└── SessionPersistence (auto-save/resume)      — reuse SessionManager pattern
```

### The Loop (per cycle)

1. LLM receives: cyber-focused system prompt + methodology knowledge + goal +
   current state summary + conversation history (tool results).
2. LLM returns either a tool call or a message.
3. Tool call → executed → raw output + structured result.
4. FlagScanner scans output. StateTracker updates. Evidence recorded.
5. Result appended to conversation; loop repeats until termination.

### Analysis of tool output (who analyzes what)

- **LLM analyzes raw output** every cycle — it reads the actual result and decides
  the next step from it (this is the anti-hallucination core: it reasons from real
  data, not from guesses).
- **Structured normalization** happens only for state updates (hosts/services/
  creds lists) so the LLM does not re-read entire history each cycle.
- **Unexpected output** (failures, refusals, timeouts) is fed back verbatim; the
  LLM adapts (retry, install tool, switch target, change technique).

### Shell tool behavior (coding-agent parity)

- `shell_exec(command)` — runs bash on the attacker box with a timeout.
- On "command not found" the LLM naturally follows up with an install
  (`apt-get install` / `pip install` / `go install`), exactly like Codex.
- `ensure_tool(tool, install_cmd)` helper available as a structured tool too.
- File tools: `read_file`, `write_file`, `list_dir` (local box, for scripts,
  wordlists, report staging).

### Safety rails (freewill, not chaos)

1. **Scope validation** — every shell command and tool call is checked against
   ROE (target CIDR / allowed hosts). IPs outside scope → command rejected and
   the rejection is fed back to the LLM. Reuses `core/scope/rules.py`.
2. **Destructive command blocklist** — `rm -rf /`, `mkfs`, `dd` on block devices,
   etc. are rejected (allowlist exceptions via config if a user insists).
3. **Termination conditions** — any one ends the run:
   - objective completed (LLM declares it or flag found)
   - flag found (regex `flag{...}`, `CTF{...}`, `PENAI{...}` — configurable)
   - max cycles reached (default 100, configurable)
   - no-progress streak (default 8 cycles without any new state change) →
     agent is told to change strategy once, then stops
   - user interrupt (Ctrl+C)
4. **Evidence & reporting** — every tool call/result is logged; findings go through
   the existing evidence collector and `ReportGenerator` (CVSS auto-scored).

### System prompt (cyber-focused alignment)

Built once at start, includes:
- Role definition (PEN-AI self-driving pentester)
- Goal + target/scope (from CLI)
- Methodology knowledge: all `knowledge/methodology_data.py` entries serialized
  into the prompt (23 entries today — small enough to fit; expanded later)
- Decision framework: analyze output → hypothesize → decide → act → verify
- Tool usage guidance (prefer structured tools for evidence; shell for everything
  else; install missing tools yourself; never stop early; always document)
- Scope rules (never target outside scope — enforced by code, not just prompt)

## CLI Wiring

```
pen-ai <target> [objective]
  → FreewillAgent(target, objective) → start loop → report on termination

pen-ai <target> "discovery network enum recon exploit pivot loop until flag"
  → objective passed verbatim as the GOAL in the system prompt
```

Existing commands (`scan`, `sessions`, `tools`, interactive REPL) unchanged.
`pen-ai engage ...` (MasterAgent path) unchanged — menu machinery is left intact
for offline/no-LLM fallback; the FreewillAgent path is the new default when a
target is given.

## Deprecation policy

- `MasterAgent.run_cycle` stays (used by CLI engage / offline fallback), but the
  FreewillAgent becomes the primary self-driving path.
- `Planner` / `Reasoner` untouched for now (fallback), documented as menu-mode.

## Error handling

- LLM API failures → retry with backoff (3 attempts), then continue last-known-good.
- Shell failures → result fed back, LLM decides (retry/install/change).
- Scope violation → rejection message fed back, LLM must pick another action.
- Malformed tool calls → sanitized, single retry with correction message.

## Testing (TDD, offline)

- Fake LLM (scripted responses / tool-call sequences) drives the loop.
- Fake executor for shell (no real commands on dev machines).
- Cases: happy path recon→exploit, tool-not-found→install→retry, scope violation
  rejection, flag detection termination, no-progress termination, max-cycle
  termination, objective completion → report artifact written.
- Full suite must stay green (current: 205 passed, 2 pre-existing Windows-only
  failures in `tests/test_autonomous.py`).

## Out of scope (this iteration)

- Expanding the knowledge base beyond the 23 entries (follow-up).
- Interactive chat mode with the agent (REPL exists; not part of this loop).
- Replacing AD/binary/IoT placeholder modules (separate effort, tracked in
  HONEST_AUDIT.md).