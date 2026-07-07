"""
client_app.py — Victim orchestrator. Connects to api_server.py's SSE stream and
splits the single byte stream into two INDEPENDENT, DECOUPLED pipelines:

  1. Cognitive pipeline   (UI render)   -> prints text_delta chunks to stdout
                                           the instant they arrive.
  2. Administrative pipeline (billing)  -> parses the message_delta usage frame
                                           and persists token counts to
                                           telemetry_state.json.

Structural assumption under test: many real client SDKs run rendering and
telemetry/accounting off the SAME network read loop but in separate consumer
contexts (e.g. a UI callback vs. an async logging hook) with independent error
boundaries — a parse exception in the telemetry consumer must not, and in
practice does not, roll back or halt the UI consumer, because the UI consumer
already committed its output. This client intentionally implements that
architecture so the failure mode can be observed empirically, not asserted.

Usage: python client_app.py <vector: none|a|b|c> [chunks]
"""
import json
import os
import queue
import socket
import sys
import threading

HOST = "127.0.0.1"
PORT = 8080
STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telemetry_state.json")


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


def parse_sse_frames(raw: bytes):
    """Split raw SSE bytes into (event, data_str) tuples. Consumes only complete
    frames (terminated by a blank line); leftover partial bytes are returned."""
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


def cognitive_worker(cog_q: "queue.Queue", rendered_chars: list):
    """Pipeline 1: renders text the instant it is dequeued. Never touches
    telemetry state. A failure here would stop text from appearing."""
    print("[cognitive ] render pipeline started")
    while True:
        item = cog_q.get()
        if item is None:
            break
        event, data = item
        if event == "content_block_delta":
            try:
                obj = json.loads(data)
                text = obj["delta"]["text"]
                sys.stdout.write(text)
                sys.stdout.flush()
                rendered_chars.append(text)
            except json.JSONDecodeError:
                # Text frames in this lab are always well-formed; this branch
                # exists only to show the render path has its own boundary.
                print("\n[cognitive ] !! malformed text frame, skipping", file=sys.stderr)
    print("\n[cognitive ] render pipeline finished")


def admin_worker(admin_q: "queue.Queue", result: dict):
    """Pipeline 2: only this worker is allowed to write telemetry_state.json.
    If json.loads() raises on a malformed usage frame, THIS THREAD dies here —
    it does not propagate to the cognitive thread or the main thread."""
    print("[admin     ] telemetry pipeline started")
    while True:
        item = admin_q.get()
        if item is None:
            break
        event, data = item
        if event == "message_delta":
            try:
                obj = json.loads(data)
                tokens = obj["usage"]["output_tokens"]
                write_state({
                    "output_tokens": tokens,
                    "stop_reason": obj.get("delta", {}).get("stop_reason"),
                    "last_update": "message_delta parsed successfully",
                    "admin_pipeline_status": "committed",
                })
                result["admin_committed"] = True
                print(f"\n[admin     ] committed usage: {tokens} tokens")
            except json.JSONDecodeError as e:
                # VECTOR A manifests here: this thread crashes/exits WITHOUT
                # ever calling write_state(). telemetry_state.json is left at
                # whatever it was set to before the stream (0 / pre-stream).
                result["admin_crashed"] = True
                result["admin_crash_reason"] = str(e)
                print(f"\n[admin     ] !! CRASHED parsing usage frame: {e}", file=sys.stderr)
                return  # thread dies silently; process keeps running
        elif event == "message_stop":
            result["admin_saw_message_stop"] = True
    print("\n[admin     ] telemetry pipeline finished")


def run(vector: str, n_chunks: int) -> dict:
    """Wire up the two pipelines and the single network reader that feeds
    both. Nothing here is unusual by real-world SDK standards — a queue
    handing frames off to a UI callback while a separate consumer tracks
    usage is a completely ordinary design. That ordinariness is the point:
    this is not a contrived worst-case, it's the default shape of a
    streaming client that nobody has stress-tested against a torn stream.
    """
    reset_state()
    rendered_chars = []
    result = {
        "vector": vector,
        "admin_committed": False,
        "admin_crashed": False,
        "admin_saw_message_stop": False,
        "network_error": None,
    }

    cog_q: "queue.Queue" = queue.Queue()
    admin_q: "queue.Queue" = queue.Queue()

    cog_t = threading.Thread(target=cognitive_worker, args=(cog_q, rendered_chars), daemon=True)
    admin_t = threading.Thread(target=admin_worker, args=(admin_q, result), daemon=True)
    cog_t.start()
    admin_t.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.sendall(f"GET /v1/messages?vector={vector}&chunks={n_chunks} HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())

    buf = b""
    header_done = False
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                # VECTOR C manifests here, silently: recv() returning b""
                # means a clean FIN, which raises NO exception at all. This
                # branch is indistinguishable, at the socket layer, from a
                # server that simply finished sending — which is exactly why
                # a client that only reasons about exceptions (rather than
                # tracking "did I actually reach a terminal protocol state?")
                # will treat a truncated stream as a normal one.
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
                # Demux: text-render frames go to the Cognitive queue,
                # usage/lifecycle frames go to the Administrative queue.
                # Both consumers are independent threads/error boundaries.
                if event == "content_block_delta":
                    cog_q.put((event, data))
                elif event in ("message_delta", "message_stop"):
                    admin_q.put((event, data))
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        # VECTOR B manifests here: the network reader dies mid-read, but every
        # content_block_delta frame that arrived BEFORE the reset was already
        # dispatched to cog_q above, so the render pipeline already has 100%
        # of the text queued/printed by the time this exception fires.
        result["network_error"] = f"{type(e).__name__}: {e}"
        print(f"\n[network   ] !! connection died: {result['network_error']}", file=sys.stderr)
    finally:
        sock.close()

    cog_q.put(None)
    admin_q.put(None)
    cog_t.join(timeout=2)
    admin_t.join(timeout=2)

    result["rendered_text"] = "".join(rendered_chars)
    result["rendered_word_count"] = len("".join(rendered_chars).split())
    return result


if __name__ == "__main__":
    vector = sys.argv[1] if len(sys.argv) > 1 else "none"
    n_chunks = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    res = run(vector, n_chunks)
    print("\n--- client_app run summary ---")
    print(json.dumps(res, indent=2))
