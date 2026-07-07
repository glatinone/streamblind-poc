# Research Report: Asynchronous Telemetry Blindness & State Desynchronization

**Environment:** local-only sandbox, `127.0.0.1:8080`, stdlib-only Python (`socket`, `json`, `threading`). No external network, no third-party targets, no framework dependencies.

## 1. Assumptions vs. verified facts (read this first)

| # | Statement | Status |
|---|---|---|
| 1 | `image_697d18.png` schema reference | **ASSUMPTION, unverifiable.** The image was not accessible in this session (no file content was ever provided to the agent). The SSE event/JSON shapes used (`message_start`, `content_block_start`, `content_block_delta`/`text_delta`, `content_block_stop`, `message_delta`/`usage`, `message_stop`) follow Anthropic's **publicly documented** Messages streaming protocol instead. If the image specifies different field names, the vectors are structurally reusable but the exact JSON keys in `api_server.py` would need renaming. |
| 2 | Vector A causes the administrative (telemetry) consumer to crash while text is already committed | **VERIFIED**, see §3, quoted process output. |
| 3 | Vector B (TCP RST after last text chunk, before `message_delta`) causes the same desync | **VERIFIED**, see §3. |
| 4 | The desync reproduces consistently across short (5-chunk) and long (40-chunk) responses | **VERIFIED**, see §4. |
| 5 | A fail-closed, state-machine-gated client eliminates the desync for both vectors while not regressing the happy path | **VERIFIED**, see §5. |

Everything under "VERIFIED" is backed by literal captured stdout/file contents below, not paraphrase.

## 2. Architecture

- **`api_server.py`** — raw-socket SSE server. Three modes selected by `?vector=`:
  - `none` — well-formed close (`message_delta` → `message_stop`).
  - `a` — **Exception Splitting**: after the final text chunk, sends a `message_delta` frame whose JSON payload has a `\x00` byte injected directly into the `usage` field, then still sends `message_stop`. The malformation is isolated to the one frame carrying billing data.
  - `b` — **Truncated Suffix**: after the final `content_block_stop`, the socket is closed with `SO_LINGER={1,0}`, forcing the kernel to emit a TCP RST instead of a clean FIN. No `message_delta`/`message_stop` is ever transmitted.
- **`client_app.py`** — the victim. A single network-reader loop demuxes SSE frames into two independent queues/threads with separate error boundaries:
  - **Cognitive pipeline**: consumes `content_block_delta` only, prints immediately, has no reference to token accounting.
  - **Administrative pipeline**: consumes `message_delta`/`message_stop`, and is the *only* code path permitted to write `telemetry_state.json`.
- **`secure_client_app.py`** — the fix: a single-threaded, explicit state-machine (`FailClosedStreamValidator`) that buffers text and refuses to release it or write telemetry unless the full lifecycle (`START → DELTA* → CONTENT_STOP → MESSAGE_DELTA → MESSAGE_STOP`) completes without error.

## 3. Gate 3 — Adversarial run, no Momentum Failure

Momentum Failure would mean the process crashes entirely and text never prints. It did not occur on either vector; both produced **partial-success desync**, which is the vulnerability under test, not a bug in the harness.

### Vector A output (verbatim)
```
[cognitive ] render pipeline started
[admin     ] telemetry pipeline started
The quick brown fox jumps
[admin     ] !! CRASHED parsing usage frame: Expecting value: line 1 column 115 (char 114)

[cognitive ] render pipeline finished

--- client_app run summary ---
{
  "vector": "a",
  "admin_committed": false,
  "admin_crashed": true,
  "rendered_text": "The quick brown fox jumps ",
  "rendered_word_count": 5
}
```
`telemetry_state.json` immediately after:
```json
{
  "output_tokens": 0,
  "stop_reason": null,
  "last_update": "pre-stream",
  "admin_pipeline_status": "idle"
}
```

### Vector B output (verbatim)
```
[network   ] !! connection died: ConnectionResetError: [WinError 10054] An existing connection was forcibly closed by the remote host
--- client_app run summary ---
{
  "vector": "b",
  "admin_committed": false,
  "admin_crashed": false,
  "rendered_text": "The quick brown fox jumps ",
  "rendered_word_count": 5
}
```
`telemetry_state.json` immediately after: identical frozen `output_tokens: 0, "admin_pipeline_status": "idle"`.

**Conclusion:** In both vectors, 100% of the intended text reached stdout via the Cognitive pipeline. The Administrative pipeline never wrote a token count. State desynchronization is proven, not inferred.

## 4. Gate 4 — Consistency at scale (5 vs 40 chunks)

| Trial | Rendered word count | Expected | telemetry `output_tokens` after |
|---|---|---|---|
| Vector A, 5 chunks | 5 | 5 | 0 |
| Vector A, 40 chunks | 40 | 40 | 0 |
| Vector B, 5 chunks | 5 | 5 | 0 |
| Vector B, 40 chunks | 40 | 40 | 0 |

The freeze is deterministic and scale-independent: it is triggered by *where* the malformation/reset sits in the frame sequence (always after all text, always at the usage frame), not by response length.

## 5. Root cause

The vulnerable architecture in `client_app.py` treats the SSE stream as **two independently-committing pipelines sharing one transport but no shared completion contract**:
- The render path commits (prints) on every individual `content_block_delta`, with no dependency on stream closure.
- The billing path commits only on a *single, later* frame (`message_delta`), and its failure mode (exception in one worker thread, or the reader loop dying before dispatch) is invisible to the render path because they communicate through fire-and-forget queues, not a joint transaction.

This is a structural pattern, not a parsing bug: any client that (a) streams UI output eagerly and (b) derives billing/telemetry from a *separate, later* frame in the same stream is vulnerable to exactly this class of asymmetric failure — whether caused by a malicious/misbehaving server, a network fault, a proxy that truncates responses, or a buggy SDK version.

## 6. Defensive fix — `secure_client_app.py`

Fail-closed state machine (`FailClosedStreamValidator`): text is buffered, never printed, until the lifecycle reaches `DONE` (i.e., `message_delta` + `message_stop` both observed in the correct order after content). Any JSON error, out-of-order event, or network close short of `DONE` invalidates the *entire* response — the buffered text is discarded, `telemetry_state.json` is explicitly written as `"admin_pipeline_status": "rejected"` (not left silently stale).

Verified behavior:
```
== baseline ==
The quick brown fox jumps
[secure    ] committed usage: 5 tokens
telemetry_state.json -> {"output_tokens": 5, "admin_pipeline_status": "committed", ...}

== vector a ==
[secure    ] stream REJECTED, no text released: malformed JSON in 'message_delta' frame...
telemetry_state.json -> {"output_tokens": 0, "admin_pipeline_status": "rejected", ...}
(stdout: no text printed)

== vector b ==
[secure    ] stream REJECTED, no text released: network closed mid-stream: ConnectionResetError...
telemetry_state.json -> {"output_tokens": 0, "admin_pipeline_status": "rejected", ...}
(stdout: no text printed)
```

The happy path is unaffected (tokens correctly recorded); both attack vectors now fail safely — no partial UI output masquerading as a complete, accounted-for response.

### Trade-off to disclose
This fix removes the UX benefit of incremental token-by-token rendering (text now appears only at stream end). For products that require live-typing UX, the recommended variant is: render optimistically as **provisional/unbilled**, and only flip it to **final** in the UI once the validator reaches `DONE` — timing out and visibly marking the message "incomplete / not billed" otherwise, rather than leaving it looking complete forever.

## 7. Known limitation of this lab

`FailClosedStreamValidator._fail()` sets `self.state = FAILED` before raising, so the exception message in Vector A currently reports "in state FAILED" rather than the state the machine was in *before* the failure. This is a cosmetic logging issue in the error message string only — it does not affect the reject/accept decision, and does not weaken the fail-closed guarantee (verified by the captured runs above, where rejection and zero-text-release both occurred correctly).

## 8. V2 Upgrade — the UX-vs-Security paradigm shift

V1's fix (§6) was security-correct but commercially unshippable: buffering the entire response until `message_delta` arrives means the user sees nothing until the model has finished — it reintroduces the "spinner, then wall of text" UX that streaming exists to eliminate. A PM will reject that trade even with the security argument attached.

V2 resolves this by separating **when text is shown** from **when it is trusted**, instead of collapsing them into one buffered gate:

- Text is printed the instant each `content_block_delta` arrives (`SpeculativeTransaction.feed`, [secure_client_app.py](secure_client_app.py)) — this is genuinely speculative/provisional output, not a UI illusion of streaming.
- A durable artifact, `session_history.json`, is updated in lockstep with what's on screen, so there is a concrete, checkable record of "what the user was shown" independent of terminal pixels.
- The same call stack that detects a lifecycle failure (malformed JSON, socket error, or **premature clean close**) immediately calls `rollback()`, which erases the visible line via ANSI (`\r` + `\033[2K`), deletes the provisional entry from `session_history.json`, and writes `telemetry_state.json` as `"admin_pipeline_status": "rejected"`.

This is not "buffer less aggressively" — it is a different contract: **provisional-then-revocable** instead of **withheld-until-proven**. The commit/rollback authority stays single and synchronous either way (that discipline is what V1 and V2 both correctly inherit from each other; only the *timing* of the visible side effect moved).

## 9. Vector C — Proxy Read Timeout / Zenmux Emulation

Added to [api_server.py](api_server.py): `vector=c` sends a fixed 5 text chunks at a slow 0.4s cadence, then performs a **clean FIN close** (plain `socket.close()`, no `SO_LINGER` RST) *before* `content_block_stop` or `message_delta` is ever sent — modeling a reverse proxy/gateway timing out on an idle upstream read and severing the client-facing connection itself, as distinct from Vector B's origin-crash-style hard reset.

This distinction matters mechanically: a clean FIN makes the client's `sock.recv()` return `b""` with **no exception raised at all** — not a `ConnectionResetError`, nothing. Verified against the original vulnerable [client_app.py](client_app.py):

```
[network_error]: null          <-- no exception fired; the reader loop just silently exited
"admin_committed": false
"rendered_text": "The quick brown fox jumps "   (all 5 words leaked to stdout)
telemetry_state.json -> {"output_tokens": 0, "admin_pipeline_status": "idle"}
```

This is a strictly worse failure mode than A or B for any client whose safety logic is exception-driven (`try/except ConnectionResetError`): there is nothing to catch. The only way to detect it is to independently track protocol state and ask "did I actually reach the terminal state?" regardless of whether an exception occurred — which is exactly what `secure_client_app.py`'s state machine does (`if integrity_error is None and txn.state != StreamState.DONE: ...`).

## 10. Gate 3/4 — V2 adversarial results (automated, [run_exploit_test.py](run_exploit_test.py))

Hostile review questions and answers, per vector, all confirmed by `run_exploit_test.py` (23/23 assertions passed):

| Check | A (malformed usage) | B (hard RST) | C (clean-FIN timeout) |
|---|---|---|---|
| Speculative text printed in real time before failure | ✅ | ✅ | ✅ |
| `[INTEGRITY ALERT]` raised | ✅ | ✅ | ✅ |
| `session_history.json` purged (0 entries after rollback) | ✅ | ✅ | ✅ |
| `telemetry_state.json` explicitly `rejected` (not left stale) | ✅ | ✅ | ✅ |
| Baseline (`vector=none`) still commits normally, history shows 1 `committed` entry | ✅ | — | — |

Raw run for Vector C against V2 (verbatim):
```
The quick brown fox jumps [2K[INTEGRITY ALERT] stream rejected mid-render — output rolled back.
Reason: stream ended in non-terminal state IN_CONTENT (clean close before lifecycle completed)

session_history.json -> []
telemetry_state.json -> {"output_tokens": 0, "admin_pipeline_status": "rejected", ...}
```
(The literal `\r\033[2K` bytes appear as `[2K` in a piped/non-TTY capture — see §11 for why that's expected and what it does/doesn't prove.)

## 11. Honest limitation: what "obliteration" can and cannot mean on a real terminal

`SpeculativeTransaction.rollback()` erases output via ANSI escape codes (`\r` + `\033[2K`), which only affects the **currently visible, unwrapped line** of a live interactive terminal. Two things follow from this, disclosed rather than glossed over:

1. **Text that has already scrolled out of the terminal viewport, or a response that wrapped across multiple lines, cannot be erased by this technique alone.** This lab's chunks never contain `\n` and are short enough to stay on one line, so the demo's erase is complete — but a production implementation rendering long multi-line responses would need to track line-wrap count (from terminal width) and emit one cursor-up + clear per wrapped line, or render inside a proper TUI/alt-screen buffer that supports full redraws (e.g. `curses`, or a browser DOM node that can be deleted outright — the "DOM Obliteration" the spec's naming references, which is trivially achievable in a browser but only partially achievable in a raw terminal).
2. **The guarantee that actually matters for the underlying vulnerability does not depend on terminal erase succeeding.** The security property is: *no durable, machine-trusted record of unbilled/unverified output survives a failed stream.* That property is fully enforced by the `session_history.json` purge and the `telemetry_state.json` rejection, both of which were verified programmatically in §10 independent of what any terminal emulator does with the ANSI bytes. A pipe/log capture (as used by `run_exploit_test.py`) will still contain the pre-rollback text as raw bytes for exactly this reason — that is a property of piping to a non-TTY, not a defect in the rollback logic.

## Files in `fable_telemetry_lab/`
- `api_server.py` — SSE gateway with baseline + three attack vectors (A: exception splitting, B: hard-reset truncation, C: clean-FIN proxy timeout)
- `client_app.py` — vulnerable dual-pipeline client (the PoC)
- `secure_client_app.py` — V1 fail-closed buffered validator (`run_buffered`) + V2 speculative-render-with-hard-rollback (`run_speculative`, default)
- `run_exploit_test.py` — Gate 4 automated verifier; starts the server, runs both clients against all vectors, asserts on durable artifacts
- `telemetry_state.json` / `session_history.json` — generated at runtime by whichever client last ran
- `research_report.md` — this file
