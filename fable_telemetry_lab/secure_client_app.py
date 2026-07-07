"""
secure_client_app.py — Defensive architecture blueprint.

V1 (`FailClosedStreamValidator` / `run_buffered`): buffers ALL text until the
stream is proven complete, then releases it atomically with telemetry. Fully
safe, but destroys streaming UX — kept here only as a baseline for comparison.

V2 (`SpeculativeTransaction` / `run_speculative`, the DEFAULT strategy): prints
each text delta to stdout the instant it arrives (real streaming UX), while a
single control-flow-resident transaction tracks everything printed. If the
stream fails to reach a verified DONE state for ANY reason — malformed usage
JSON (Vector A), hard TCP reset (Vector B), or clean-FIN proxy timeout cutting
the stream before content_block_stop/message_delta (Vector C) — the SAME
thread that detected the failure immediately:
  1. emits ANSI erase sequences to wipe the currently-visible printed segment,
  2. deletes the provisional entry from session_history.json (the durable
     "local chat history" artifact — this is the part that must never leak,
     since real terminal scrollback that has already scrolled off-screen
     cannot literally be un-printed; see research_report.md V2 section for
     this disclosed limitation),
  3. writes telemetry_state.json as explicitly "rejected" (never left stale),
  4. prints a "[INTEGRITY ALERT]" banner.

Design principle carried over from V1: rollback is invoked from the same call
stack that detected the failure — never from a second, decoupled pipeline
communicating over a fire-and-forget queue. That decoupling is exactly the
structural flaw client_app.py demonstrates.
"""
import json
import os
import socket
import sys
from enum import Enum, auto

HOST = "127.0.0.1"
PORT = 8080
STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telemetry_state.json")
HISTORY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "session_history.json")

ANSI_CLEAR_LINE = "\033[2K"
ANSI_CURSOR_TO_START = "\r"


class StreamState(Enum):
    EXPECT_MESSAGE_START = auto()
    EXPECT_CONTENT_START = auto()
    IN_CONTENT = auto()
    EXPECT_MESSAGE_DELTA = auto()
    EXPECT_MESSAGE_STOP = auto()
    DONE = auto()
    FAILED = auto()


def write_state(state: dict):
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def reset_state():
    write_state({
        "output_tokens": 0,
        "stop_reason": None,
        "last_update": "pre-stream",
        "admin_pipeline_status": "idle",
    })


def read_history() -> list:
    if not os.path.exists(HISTORY_PATH):
        return []
    with open(HISTORY_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def write_history(entries: list):
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def parse_sse_frames(raw: bytes):
    """Split raw SSE bytes into (event, data_str) tuples. Consumes only
    complete frames (terminated by a blank line); leftover partial bytes are
    returned so the caller can prepend them to the next recv() chunk. This
    hand-rolled demuxer is a stand-in for whatever framing layer a real SDK
    ships — the vulnerability we're defending against lives ABOVE this layer,
    in what the caller does with a frame once it's fully parsed."""
    frames = []
    while True:
        sep = raw.find(b"\n\n")
        if sep == -1:
            break
        block, raw = raw[:sep], raw[sep + 2:]
        event, data = None, None
        for line in block.split(b"\n"):
            if line.startswith(b"event: "):
                event = line[len(b"event: "):].decode("utf-8", "replace")
            elif line.startswith(b"data: "):
                data = line[len(b"data: "):].decode("utf-8", "replace")
        if event is not None and data is not None:
            frames.append((event, data))
    return frames, raw


class FailClosedStreamValidator:
    """V1 defense: drives the lifecycle state machine but WITHHOLDS text.
    Buffers every delta silently; only exposes it via `.finalize()` once the
    whole lifecycle is verified end-to-end. Any anomaly raises
    StreamIntegrityError and the caller MUST discard partial text.

    This is the "safe but slow-feeling" answer to the problem: correctness by
    construction, at the cost of the very streaming UX the product needs.
    Kept fully intact here so it can be measured against V2 rather than
    taken on faith — see run_exploit_test.py and research_report.md §6."""

    def __init__(self):
        self.state = StreamState.EXPECT_MESSAGE_START
        self._buffer_chars = []
        self.usage_tokens = None
        self.stop_reason = None

    def feed(self, event: str, data: str):
        if self.state == StreamState.FAILED:
            return  # already dead; ignore further input

        try:
            obj = json.loads(data)
        except json.JSONDecodeError as e:
            self.state = StreamState.FAILED
            raise StreamIntegrityError(
                f"malformed JSON in '{event}' frame while in state "
                f"{self.state.name}: {e}"
            )

        if event == "message_start":
            if self.state != StreamState.EXPECT_MESSAGE_START:
                self._fail(f"unexpected message_start in state {self.state.name}")
            self.state = StreamState.EXPECT_CONTENT_START

        elif event == "content_block_start":
            if self.state != StreamState.EXPECT_CONTENT_START:
                self._fail(f"unexpected content_block_start in state {self.state.name}")
            self.state = StreamState.IN_CONTENT

        elif event == "content_block_delta":
            if self.state != StreamState.IN_CONTENT:
                self._fail(f"content_block_delta outside IN_CONTENT state ({self.state.name})")
            # Buffer only — NOT rendered to the user yet.
            self._buffer_chars.append(obj["delta"]["text"])

        elif event == "content_block_stop":
            if self.state != StreamState.IN_CONTENT:
                self._fail(f"content_block_stop in state {self.state.name}")
            self.state = StreamState.EXPECT_MESSAGE_DELTA

        elif event == "message_delta":
            if self.state != StreamState.EXPECT_MESSAGE_DELTA:
                self._fail(f"message_delta in state {self.state.name}")
            self.usage_tokens = obj["usage"]["output_tokens"]
            self.stop_reason = obj.get("delta", {}).get("stop_reason")
            self.state = StreamState.EXPECT_MESSAGE_STOP

        elif event == "message_stop":
            if self.state != StreamState.EXPECT_MESSAGE_STOP:
                self._fail(f"message_stop in state {self.state.name}")
            self.state = StreamState.DONE

    def _fail(self, reason: str):
        self.state = StreamState.FAILED
        raise StreamIntegrityError(reason)

    def finalize(self) -> dict:
        """Only call after the read loop ends. Raises if the lifecycle never
        reached DONE — this is the fail-closed gate."""
        if self.state != StreamState.DONE:
            raise StreamIntegrityError(
                f"stream ended in non-terminal state {self.state.name}; "
                f"refusing to commit text or telemetry"
            )
        return {
            "text": "".join(self._buffer_chars),
            "output_tokens": self.usage_tokens,
            "stop_reason": self.stop_reason,
        }


class StreamIntegrityError(Exception):
    pass


def run_buffered(vector: str, n_chunks: int) -> dict:
    """V1 strategy: safe, but no incremental UX. Kept for comparison."""
    reset_state()
    validator = FailClosedStreamValidator()
    result = {"vector": vector, "committed": False, "error": None}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.sendall(f"GET /v1/messages?vector={vector}&chunks={n_chunks} HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())

    buf = b""
    header_done = False
    integrity_error = None
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if not header_done:
                sep = buf.find(b"\r\n\r\n")
                if sep == -1:
                    continue
                buf = buf[sep + 4:]
                header_done = True

            frames, buf = parse_sse_frames(buf)
            for event, data in frames:
                validator.feed(event, data)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        integrity_error = f"network closed mid-stream: {type(e).__name__}: {e}"
    except StreamIntegrityError as e:
        integrity_error = str(e)
    finally:
        sock.close()

    if integrity_error is None:
        try:
            final = validator.finalize()
        except StreamIntegrityError as e:
            integrity_error = str(e)

    if integrity_error is not None:
        # FAIL CLOSED: nothing is printed, nothing is committed to telemetry.
        write_state({
            "output_tokens": 0,
            "stop_reason": None,
            "last_update": f"REJECTED: {integrity_error}",
            "admin_pipeline_status": "rejected",
        })
        print(f"[secure    ] stream REJECTED, no text released: {integrity_error}", file=sys.stderr)
        result["error"] = integrity_error
        return result

    # Only now, atomically, do we release text AND commit telemetry.
    sys.stdout.write(final["text"])
    sys.stdout.flush()
    write_state({
        "output_tokens": final["output_tokens"],
        "stop_reason": final["stop_reason"],
        "last_update": "message_delta parsed successfully",
        "admin_pipeline_status": "committed",
    })
    result["committed"] = True
    result["rendered_text"] = final["text"]
    print(f"\n[secure    ] committed usage: {final['output_tokens']} tokens")
    return result


class SpeculativeTransaction:
    """V2 strategy core. Prints text the instant it arrives (speculative /
    provisional), while tracking exactly what was printed so it can be
    surgically erased and purged from durable storage on rollback.

    NOTE on the erase guarantee: ANSI escapes (\\r + \\033[2K) can only erase
    the CURRENTLY VISIBLE line(s) of a real terminal. Text that has already
    scrolled out of the viewport cannot be recalled from a live TTY — this is
    a physical property of terminal scrollback, not a bug in this transaction.
    The guarantee this class actually provides, and the one that matters for
    the underlying vulnerability, is over DURABLE state: session_history.json
    and telemetry_state.json are always left correctly rolled back / rejected,
    regardless of what a real terminal's scrollback still shows.
    """

    def __init__(self):
        self.state = StreamState.EXPECT_MESSAGE_START
        self._printed_segments = []  # for ANSI erase bookkeeping
        self._history_index = None   # index of our provisional entry in session_history.json
        self.usage_tokens = None
        self.stop_reason = None

        history = read_history()
        history.append({"role": "assistant", "status": "provisional", "text": ""})
        self._history_index = len(history) - 1
        write_history(history)

    def _append_history_text(self, text: str):
        history = read_history()
        history[self._history_index]["text"] += text
        write_history(history)

    def feed(self, event: str, data: str):
        if self.state == StreamState.FAILED:
            return

        try:
            obj = json.loads(data)
        except json.JSONDecodeError as e:
            self.state = StreamState.FAILED
            raise StreamIntegrityError(
                f"malformed JSON in '{event}' frame while in state "
                f"{self.state.name}: {e}"
            )

        if event == "message_start":
            if self.state != StreamState.EXPECT_MESSAGE_START:
                self._fail(f"unexpected message_start in state {self.state.name}")
            self.state = StreamState.EXPECT_CONTENT_START

        elif event == "content_block_start":
            if self.state != StreamState.EXPECT_CONTENT_START:
                self._fail(f"unexpected content_block_start in state {self.state.name}")
            self.state = StreamState.IN_CONTENT

        elif event == "content_block_delta":
            if self.state != StreamState.IN_CONTENT:
                self._fail(f"content_block_delta outside IN_CONTENT state ({self.state.name})")
            text = obj["delta"]["text"]
            # SPECULATIVE RENDER: printed immediately, real streaming UX.
            sys.stdout.write(text)
            sys.stdout.flush()
            self._printed_segments.append(text)
            self._append_history_text(text)

        elif event == "content_block_stop":
            if self.state != StreamState.IN_CONTENT:
                self._fail(f"content_block_stop in state {self.state.name}")
            self.state = StreamState.EXPECT_MESSAGE_DELTA

        elif event == "message_delta":
            if self.state != StreamState.EXPECT_MESSAGE_DELTA:
                self._fail(f"message_delta in state {self.state.name}")
            self.usage_tokens = obj["usage"]["output_tokens"]
            self.stop_reason = obj.get("delta", {}).get("stop_reason")
            self.state = StreamState.EXPECT_MESSAGE_STOP

        elif event == "message_stop":
            if self.state != StreamState.EXPECT_MESSAGE_STOP:
                self._fail(f"message_stop in state {self.state.name}")
            self.state = StreamState.DONE

    def _fail(self, reason: str):
        self.state = StreamState.FAILED
        raise StreamIntegrityError(reason)

    @property
    def printed_char_count(self) -> int:
        """How many characters are currently sitting on the user's screen,
        speculatively. Exposed publicly so callers can report/audit exposure
        without reaching into the undo log directly."""
        return sum(len(s) for s in self._printed_segments)

    def commit(self) -> dict:
        if self.state != StreamState.DONE:
            raise StreamIntegrityError(
                f"commit() called in non-terminal state {self.state.name}"
            )
        history = read_history()
        history[self._history_index]["status"] = "committed"
        write_history(history)
        write_state({
            "output_tokens": self.usage_tokens,
            "stop_reason": self.stop_reason,
            "last_update": "message_delta parsed successfully",
            "admin_pipeline_status": "committed",
        })
        return {
            "text": "".join(self._printed_segments),
            "output_tokens": self.usage_tokens,
            "stop_reason": self.stop_reason,
        }

    def rollback(self, reason: str):
        """HARD ROLLBACK — 'DOM Obliteration' for a terminal.
        1) erase the visible printed segment via ANSI codes
        2) purge the provisional entry from session_history.json
        3) mark telemetry_state.json rejected
        4) print an integrity alert
        """
        total_chars = sum(len(s) for s in self._printed_segments)
        if total_chars:
            # Move to column 0 and clear the (single, non-wrapped) line. This
            # lab's chunks never contain '\n', so all speculative output for
            # one transaction stays on one terminal line — documented
            # assumption; multi-line responses would need one clear per line.
            sys.stdout.write(ANSI_CURSOR_TO_START + ANSI_CLEAR_LINE)
            sys.stdout.flush()

        history = read_history()
        if self._history_index is not None and self._history_index < len(history):
            del history[self._history_index]
        write_history(history)

        write_state({
            "output_tokens": 0,
            "stop_reason": None,
            "last_update": f"REJECTED: {reason}",
            "admin_pipeline_status": "rejected",
        })

        print(f"[INTEGRITY ALERT] stream rejected mid-render — output rolled back. "
              f"Reason: {reason}", file=sys.stderr)


def run_speculative(vector: str, n_chunks: int) -> dict:
    """V2 strategy (default): real-time streaming UX with hard rollback."""
    reset_state()
    txn = SpeculativeTransaction()
    result = {"vector": vector, "committed": False, "error": None,
              "chars_printed_before_failure": 0}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.sendall(f"GET /v1/messages?vector={vector}&chunks={n_chunks} HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())

    buf = b""
    header_done = False
    integrity_error = None
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                # Clean EOF (Vector C). NOT automatically "fine" — the state
                # machine below still has to confirm DONE was reached.
                break
            buf += chunk
            if not header_done:
                sep = buf.find(b"\r\n\r\n")
                if sep == -1:
                    continue
                buf = buf[sep + 4:]
                header_done = True

            frames, buf = parse_sse_frames(buf)
            for event, data in frames:
                txn.feed(event, data)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        integrity_error = f"network closed mid-stream: {type(e).__name__}: {e}"
    except StreamIntegrityError as e:
        integrity_error = str(e)
    finally:
        sock.close()

    if integrity_error is None and txn.state != StreamState.DONE:
        integrity_error = (
            f"stream ended in non-terminal state {txn.state.name} "
            f"(clean close before lifecycle completed)"
        )

    result["chars_printed_before_failure"] = txn.printed_char_count

    if integrity_error is not None:
        txn.rollback(integrity_error)
        result["error"] = integrity_error
        return result

    final = txn.commit()
    result["committed"] = True
    result["rendered_text"] = final["text"]
    print(f"\n[secure    ] committed usage: {final['output_tokens']} tokens")
    return result


if __name__ == "__main__":
    vector = sys.argv[1] if len(sys.argv) > 1 else "none"
    n_chunks = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    strategy = sys.argv[3] if len(sys.argv) > 3 else "speculative"

    res = run_buffered(vector, n_chunks) if strategy == "buffered" else run_speculative(vector, n_chunks)
    print("\n--- secure_client_app run summary ---")
    print(json.dumps(res, indent=2))
