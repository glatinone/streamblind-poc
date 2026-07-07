"""
api_server.py — Local-only, native-Python (stdlib only) SSE gateway that emulates
the shape of an Anthropic-style Messages streaming response.

Schema reference (ASSUMPTION — see research_report.md "Assumptions" section):
the provided image_697d18.png could not be read in this session, so the SSE
event/JSON shapes below follow the publicly documented Anthropic Messages
streaming protocol: message_start -> content_block_start -> content_block_delta
(text_delta) x N -> content_block_stop -> message_delta (contains usage) ->
message_stop, each frame as `event: <type>\ndata: <json>\n\n`.

Routes (selected via query string ?vector=):
  vector=none        Baseline: fully well-formed stream. Used for Gate 1/2 connectivity proof.
  vector=a           Vector A "Exception Splitting": final message_delta usage frame has
                      a \x00 control byte injected into its JSON payload, then message_stop
                      sent normally. Malforms only the billing/usage frame.
  vector=b           Vector B "Truncated Suffix": after the last content_block_delta text
                      chunk, the raw TCP connection is hard-reset (SO_LINGER=0 -> RST) with
                      NO message_delta / message_stop ever sent.
  vector=c           Vector C "Proxy Read Timeout / Zenmux Emulation": streams a FIXED 5
                      text chunks at a deliberately slow cadence (0.4s/chunk) to simulate a
                      slow backend, then the connection is closed with a CLEAN FIN (normal
                      socket.close(), no SO_LINGER RST) BEFORE content_block_stop or
                      message_delta is ever sent — modeling a reverse proxy / gateway that
                      gives up on an idle upstream read and severs the client-facing socket
                      itself, rather than the origin model crashing (Vector B). This is a
                      distinct failure shape from Vector B: recv() on the client returns a
                      clean EOF (b""), not a ConnectionResetError exception, which is a code
                      path many clients handle as "stream simply ended" rather than "stream
                      failed" — the exact gap this vector is designed to expose.

Query params:
  chunks=N            number of text-delta chunks to simulate (default 5)

This server is for local defensive research only. It binds to 127.0.0.1.
"""
import json
import socket
import struct
import threading
import time
from urllib.parse import urlparse, parse_qs

HOST = "127.0.0.1"
PORT = 8080

# A deliberately mundane sentence. The exploit lives in *timing and framing*,
# not in payload content — any text would trigger the same desync, which is
# itself evidence that this is a structural/architectural flaw, not a
# content-parsing edge case that a smarter regex could paper over.
WORDS = ["The", "quick", "brown", "fox", "jumps", "over", "the", "lazy",
         "dog", "while", "streaming", "tokens", "one", "chunk", "at", "a", "time."]


def sse_frame(event: str, data_obj) -> bytes:
    """Serialize one well-formed Server-Sent Event frame."""
    payload = json.dumps(data_obj)
    return f"event: {event}\ndata: {payload}\n\n".encode("utf-8")


def sse_frame_raw(event: str, raw_data_str: str) -> bytes:
    """Serialize one SSE frame from a raw string, bypassing json.dumps().

    This exists ONLY so Vector A can smuggle an intentionally-invalid JSON
    body (a literal NUL byte inside the payload) onto the wire. A real
    upstream would never construct this on purpose — it stands in for
    corruption introduced by a buggy proxy, a truncating load balancer, or a
    misbehaving SDK version somewhere in the middle of the pipe.
    """
    return f"event: {event}\ndata: {raw_data_str}\n\n".encode("utf-8")


def build_stream(vector: str, n_chunks: int):
    """Generate the raw SSE frame sequence for the requested attack vector.

    Every vector shares the same opening handshake (message_start ->
    content_block_start) because the vulnerability under test is NOT about
    how a stream begins — it's about what happens at the SEAM between the
    last content frame and the final accounting frame. That seam is where
    real-world proxies, load balancers, and SDKs most often diverge from the
    happy path: mid-flight cancellations, idle-read timeouts, and malformed
    trailers all land exactly there.
    """
    msg_id = "msg_fable_lab_0001"

    yield sse_frame("message_start", {
        "type": "message_start",
        "message": {
            "id": msg_id, "type": "message", "role": "assistant",
            "model": "claude-fable-lab", "content": [],
            "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 12, "output_tokens": 0},
        },
    })
    yield sse_frame("content_block_start", {
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "text", "text": ""},
    })

    if vector == "c":
        # VECTOR C — "Proxy Read Timeout": the origin model is fine and still
        # producing tokens; the failure is injected one layer UP the stack, at
        # a reverse proxy / API gateway that gives up on an idle upstream read.
        # We simulate that by deliberately slowing the cadence (0.4s/chunk,
        # vs. the 0.05s baseline) and then returning with NO trailing frames
        # at all — the caller (handle_client) will close the socket with a
        # plain, CLEAN FIN. That distinction is the entire point of this
        # vector: a clean FIN surfaces to the client as recv() returning an
        # unremarkable empty bytes object, not an exception. Many clients
        # treat "no exception" as "nothing went wrong" — that assumption is
        # exactly what this vector exists to falsify.
        for i in range(5):
            word = WORDS[i % len(WORDS)] + " "
            yield sse_frame("content_block_delta", {
                "type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": word},
            })
            time.sleep(0.4)
        print("[api_server] vector=c: simulated proxy timeout — closing the "
              "socket before content_block_stop/message_delta were sent. "
              "A real billing proxy would log this as a 0-token dropped "
              "connection, while the client-visible bytes already show the "
              "full response.")
        return

    for i in range(n_chunks):
        word = WORDS[i % len(WORDS)] + " "
        yield sse_frame("content_block_delta", {
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": word},
        })
        time.sleep(0.05)

    yield sse_frame("content_block_stop", {"type": "content_block_stop", "index": 0})

    if vector == "b":
        # VECTOR B — "Truncated Suffix": the origin has just finished the
        # text portion of a normal response (content_block_stop was sent)
        # and is a single frame away from a fully accounted-for message —
        # then the connection dies before that frame ships. This models a
        # backend crash, an OOM kill, or a container restart landing in the
        # exact gap between "content done" and "usage reported". No
        # message_delta / message_stop is ever transmitted.
        return

    if vector == "a":
        # VECTOR A — "Exception Splitting": the stream completes structurally
        # (every frame arrives, in order) but the ONE frame carrying billing
        # data is corrupted at the byte level (a literal NUL byte inside the
        # JSON). This is deliberately narrow: it proves the vulnerability
        # does not require ANY network failure at all — a single malformed
        # byte in the accounting frame is sufficient to desynchronize a
        # client whose render path and billing path do not share a single
        # point of failure.
        malformed = (
            '{"type": "message_delta", "delta": {"stop_reason": "end_turn", '
            '"stop_sequence": null}, "usage": {"output_tokens": \x00 42}}'
        )
        yield sse_frame_raw("message_delta", malformed)
        yield sse_frame("message_stop", {"type": "message_stop"})
        return

    # vector == "none": the fully well-formed baseline. Every downstream
    # exploit is judged against this shape — if a fix breaks this path, the
    # fix has failed regardless of how well it blocks the attack vectors.
    yield sse_frame("message_delta", {
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
        "usage": {"output_tokens": n_chunks},
    })
    yield sse_frame("message_stop", {"type": "message_stop"})


def handle_client(conn: socket.socket, addr):
    """Handle one connection end-to-end: parse the minimal request line,
    stream the selected vector's frames, then tear down the socket in the
    way that vector specifically demands (clean FIN vs. hard RST). The
    teardown method is not incidental — it IS the exploit for Vector B.
    """
    try:
        conn.settimeout(5)
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = conn.recv(4096)
            if not chunk:
                return
            request += chunk

        request_line = request.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        try:
            method, path, _ = request_line.split(" ")
        except ValueError:
            conn.close()
            return

        parsed = urlparse(path)
        qs = parse_qs(parsed.query)
        vector = qs.get("vector", ["none"])[0]
        n_chunks = int(qs.get("chunks", ["5"])[0])

        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: close\r\n"
            "X-Fable-Lab-Vector: {}\r\n"
            "\r\n"
        ).format(vector)
        conn.sendall(headers.encode("utf-8"))

        for frame in build_stream(vector, n_chunks):
            conn.sendall(frame)

        if vector == "b":
            # SO_LINGER with l_onoff=1, l_linger=0 tells the kernel to
            # discard any buffered data and emit a hard RST instead of the
            # normal four-way FIN teardown. This is what turns "the server
            # stopped talking" into a genuine exception on the client side
            # (ConnectionResetError) rather than a quiet end-of-stream — the
            # deliberate opposite of Vector C's clean close below.
            conn.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )
            conn.close()
            return

        # Baseline, Vector A, and Vector C all end with an ordinary close():
        # a normal FIN handshake. For Vector C specifically, this is the
        # entire mechanism — no special socket option is needed to make a
        # "successful-looking" disconnect, which is exactly what makes it
        # dangerous.
        conn.close()
    except (ConnectionResetError, BrokenPipeError, OSError):
        # The lab client sometimes disconnects mid-write when reproducing a
        # vector; that's expected traffic for this harness, not a bug in the
        # server, so it is swallowed here rather than logged as an error.
        pass


def serve():
    """Accept loop: one daemon thread per connection. Thread-per-connection
    (rather than an async event loop) is a deliberate simplicity choice for a
    research harness — it keeps the exploit code path trivially readable at
    the cost of not scaling, which is irrelevant for a local PoC.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(16)
    print(f"[api_server] listening on http://{HOST}:{PORT}  (vector=none|a|b|c, chunks=N)")
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    serve()
