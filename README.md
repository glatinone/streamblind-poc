# StreamBlind — The Asynchronous Telemetry Desync Lab

> A local, self-contained proof-of-concept for **Asynchronous Telemetry Blindness & State Desynchronization**: the failure class where an AI streaming client renders 100% of a response while its billing/telemetry pipeline silently freezes at zero.

---

## ⚠️ Strict Disclaimer

**This repository is a defensive security research artifact.** Every component runs exclusively on `127.0.0.1`, uses only the Python standard library, and targets a server we wrote ourselves for the sole purpose of studying failure modes in *our own* code.

- ❌ No live infrastructure is attacked. No third-party API, model provider, or production system is touched, probed, or referenced by hostname.
- ❌ This is not a tool for degrading, denying, or defrauding any real service.
- ✅ It exists to help engineers, SREs, and security researchers understand a structural class of bug in **streaming AI client architecture** — and to publish a working, tested defense (`secure_client_app.py`) alongside the exploit, not instead of it.

If you build on this research, do so to harden systems, not to exploit them.

---

## Hypothesis

> **Asynchronous Telemetry Blindness & State Desynchronization**: In a client architecture that treats "showing the user text" and "recording what that text cost" as two independently-committing pipelines fed by the same stream, an attacker (or an ordinary infrastructure fault) can sever the connection at the exact seam between the last content frame and the final accounting frame — leaving the user with a complete, seemingly-successful response while the billing/telemetry layer records nothing at all.

The bug is not in JSON parsing. It's architectural: **rendering has no dependency on accounting, so accounting's failure is invisible to rendering.**

## Motivation & Objectives

Real-time token streaming is now the default UX for AI products — nobody wants to stare at a spinner while a model composes a paragraph. But the moment a team splits "render the tokens" from "count/bill the tokens" into separate consumers of the same stream (a completely natural thing to do, and something we observed is a very common real-world pattern), they've created two independent points of failure with no shared contract for what "success" means.

We set out to answer one narrow, falsifiable question:

> **Can a client render a full response to the user while its own telemetry state remains at zero — with no crash, no visible error, and no exception in some failure paths at all?**

...and then to answer the follow-up every Product Manager will ask:

> **Can we fix this without destroying the streaming UX that made the product good in the first place?**

Both are answered empirically in this repo, not asserted.

## Current Project Status

**Phase 2 complete — local simulation validated.**

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Prove the desync exists (Vector A: malformed usage frame, Vector B: hard TCP reset) against a naive dual-pipeline client | ✅ Done |
| Phase 2 | Add Vector C (clean-FIN proxy timeout — the *no-exception* case), build a production-viable fix (speculative rendering + hard rollback), automate verification | ✅ Done — 23/23 automated assertions passing |
| Phase 3 | Community review, additional vectors (HTTP/2 stream resets, chunked-encoding edge cases), packaging as an installable diagnostic tool | 🔜 Proposed |

## Testing Environment

Everything runs with **zero external dependencies** — no `requests`, no `aiohttp`, no `anthropic` SDK, no Docker. Just the Python standard library (`socket`, `json`, `threading`, `subprocess`), because the vulnerability is a property of *any* SSE client, not of a specific SDK's implementation quirks.

- **`api_server.py`** — a raw-socket HTTP/SSE server on `127.0.0.1:8080`, hand-rolled frame-by-frame, that emulates the shape of an Anthropic-style Messages streaming response (`message_start → content_block_start → content_block_delta* → content_block_stop → message_delta → message_stop`). It supports four modes via `?vector=`:
  - `none` — fully well-formed baseline.
  - `a` — **Exception Splitting**: the final `message_delta` (usage/billing frame) contains a raw NUL byte, corrupting only that frame.
  - `b` — **Truncated Suffix**: after the text finishes, the socket is hard-reset (`SO_LINGER` → RST) before `message_delta`/`message_stop` ever ship.
  - `c` — **Proxy Read Timeout**: a slow stream is cut with a *clean FIN* before even `content_block_stop` is sent — the failure a client's exception handlers are least likely to catch, because nothing raises.
- **`client_app.py`** — the vulnerable victim: a dual-pipeline client with a Cognitive (render) thread and an Administrative (telemetry) thread, decoupled by queues.
- **`secure_client_app.py`** — the fix, in two strategies:
  - `run_buffered` (V1) — fail-closed: buffer everything, release nothing until the whole lifecycle is verified.
  - `run_speculative` (V2, default) — **speculative rendering with hard rollback**: stream text in real time, but instantly wipe the screen and purge durable history the moment the lifecycle fails to reach a terminal state.
- **`run_exploit_test.py`** — an automated Gate-4 verifier: spins up the server, runs both clients against all four vectors, and asserts on durable artifacts (`telemetry_state.json`, `session_history.json`), not on trust.

## Workflow & Architecture

### The vulnerable architecture (`client_app.py`)

```
                         ┌─────────────────────────┐
                         │   api_server.py (SSE)    │
                         │  message_start           │
                         │  content_block_delta x N │
                         │  content_block_stop      │
                         │  message_delta  ◄─────── │  ← billing/usage lives HERE
                         │  message_stop            │
                         └────────────┬─────────────┘
                                      │  single TCP byte stream
                                      ▼
                         ┌─────────────────────────┐
                         │   network reader loop    │
                         │   (demuxes SSE frames)   │
                         └──────┬────────────┬──────┘
                                │            │
                content_block_delta    message_delta / message_stop
                                │            │
                                ▼            ▼
                    ┌───────────────┐  ┌────────────────────┐
                    │  COGNITIVE    │  │  ADMINISTRATIVE     │
                    │  pipeline     │  │  pipeline            │
                    │  (render)     │  │  (billing/telemetry) │
                    │               │  │                      │
                    │  prints text  │  │  writes              │
                    │  IMMEDIATELY  │  │  telemetry_state.json│
                    │  no dependency│  │  ONLY on successful  │
                    │  on stream    │  │  message_delta parse │
                    │  closure      │  │                      │
                    └───────┬───────┘  └──────────┬───────────┘
                            │                      │
                            ▼                      ▼
                     100% text on screen    ⚠ crashes / never fires
                                              on Vector A, B, or C
```

**The gap:** these two pipelines share a transport but no shared completion contract. If the Administrative pipeline dies (parse exception) or never receives its frame (reset/timeout), the Cognitive pipeline has no way to know — and no reason to care, because it already committed.

### The fix (`secure_client_app.py`, V2 speculative + hard rollback)

```
   content_block_delta arrives
            │
            ▼
   ┌────────────────────────────┐        stream reaches DONE
   │  SpeculativeTransaction     │  ───────────────────────────►  commit()
   │                             │        (message_delta +          │
   │  • print to stdout NOW      │         message_stop verified,   ▼
   │  • append to                │         in order, valid JSON)   telemetry_state.json
   │    session_history.json     │                                 → "committed"
   │    as PROVISIONAL           │
   │  • track undo log           │        stream fails ANY check   session_history.json
   │                             │  ───────────────────────────►  entry → "committed"
   └────────────────────────────┘        (malformed JSON /              │
                                           RST / clean EOF               ▼
                                           before DONE)          rollback()
                                                                    │
                                                                    ▼
                                                     ANSI-erase visible text
                                                     + purge provisional entry
                                                     + telemetry → "rejected"
                                                     + "[INTEGRITY ALERT]"
```

One control flow, one authority, two possible endings — never a silent third option where text stays on screen and telemetry stays stale.

## Expectations vs. Reality

| | **What a naive client expects** | **What actually happens under exploit** |
|---|---|---|
| **Vector A** (malformed usage frame) | Usage frame parses like every other frame; telemetry updates normally. | Text fully rendered (`admin_committed: false`, `admin_crashed: true`); `telemetry_state.json` frozen at `output_tokens: 0`. |
| **Vector B** (hard TCP reset) | A dropped connection means a dropped *response* — nothing should render. | Text fully rendered anyway (all delta frames already dispatched before the reset); telemetry frozen at 0. |
| **Vector C** (clean-FIN proxy timeout) | If something went wrong, an exception will tell us. | **No exception is raised at all** (`network_error: null`) — `recv()` just returns `b""`. Text still fully renders; telemetry still frozen at 0. This is the worst case: nothing in the client's error-handling code path even fires. |
| **V2 fix, all three vectors** | — | Text is shown in real time, then instantly wiped; `session_history.json` is purged back to `[]`; `telemetry_state.json` is explicitly written as `"admin_pipeline_status": "rejected"` — never left ambiguous. |

Full verbatim process output, file contents, and the 23-assertion automated test log are in [`fable_telemetry_lab/research_report.md`](fable_telemetry_lab/research_report.md).

## Repository Layout

```
streamblind-poc/
├── README.md                        ← you are here
├── LICENSE
├── .gitignore
└── fable_telemetry_lab/
    ├── api_server.py                ← SSE gateway: baseline + 3 attack vectors
    ├── client_app.py                ← vulnerable dual-pipeline client (the PoC)
    ├── secure_client_app.py         ← V1 fail-closed + V2 speculative/rollback fix
    ├── run_exploit_test.py          ← automated Gate-4 verifier (23 assertions)
    └── research_report.md           ← full findings, verbatim evidence, disclosed assumptions
```

## Running it yourself

```bash
cd fable_telemetry_lab

# Terminal 1
python api_server.py

# Terminal 2 — reproduce the vulnerability
python client_app.py a 5      # Exception Splitting
python client_app.py b 5      # Truncated Suffix
python client_app.py c 5      # Proxy Read Timeout (the no-exception case)

# Terminal 2 — verify the fix
python secure_client_app.py a 5   # watch it stream, then roll back live

# Or just run the full automated suite end-to-end:
python run_exploit_test.py
```

## License

MIT — see [`LICENSE`](LICENSE). Use this to build safer streaming clients, not to break existing ones.
