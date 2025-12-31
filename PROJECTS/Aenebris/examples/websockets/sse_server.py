#!/usr/bin/env python3
"""
Server-Sent Events (SSE) Streaming Server for Aenebris testing
"""

import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime


class SSEHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy"}).encode())
            return

        if self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            print(f"[SSE] Client connected: {self.client_address}")

            try:
                event_id = 0
                while True:
                    event_id += 1
                    data = {
                        "id": event_id,
                        "timestamp": datetime.now().isoformat(),
                        "message": f"Event #{event_id}"
                    }

                    event = f"id: {event_id}\nevent: tick\ndata: {json.dumps(data)}\n\n"
                    self.wfile.write(event.encode())
                    self.wfile.flush()

                    print(f"[SSE] Sent event #{event_id}")
                    time.sleep(1)

            except (BrokenPipeError, ConnectionResetError):
                print(f"[SSE] Client {self.client_address} disconnected")
            return

        if self.path == "/stream/fast":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            print(f"[SSE-FAST] Client connected: {self.client_address}")

            try:
                for i in range(100):
                    data = {"seq": i, "ts": datetime.now().isoformat()}
                    event = f"data: {json.dumps(data)}\n\n"
                    self.wfile.write(event.encode())
                    self.wfile.flush()
                    time.sleep(0.05)

                self.wfile.write(b"event: done\ndata: complete\n\n")
                self.wfile.flush()
                print(f"[SSE-FAST] Stream complete")

            except (BrokenPipeError, ConnectionResetError):
                print(f"[SSE-FAST] Client disconnected early")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html = """<!DOCTYPE html>
<html>
<head><title>SSE Test</title></head>
<body>
<h1>SSE Test Endpoints</h1>
<ul>
  <li><a href="/events">/events</a> - Continuous 1-second ticks</li>
  <li><a href="/stream/fast">/stream/fast</a> - Fast burst (100 events)</li>
  <li><a href="/health">/health</a> - Health check</li>
</ul>
<h2>Live Events:</h2>
<pre id="output"></pre>
<script>
const es = new EventSource('/events');
es.onmessage = (e) => {
  document.getElementById('output').textContent += e.data + '\\n';
};
es.addEventListener('tick', (e) => {
  document.getElementById('output').textContent += e.data + '\\n';
});
</script>
</body>
</html>"""
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        print(f"[HTTP] {format % args}")


if __name__ == "__main__":
    port = 8003
    server = HTTPServer(("localhost", port), SSEHandler)
    print(f"SSE server running on http://localhost:{port}")
    print("Endpoints:")
    print("  /events      - Continuous SSE stream (1 event/sec)")
    print("  /stream/fast - Fast burst stream (100 events)")
    print("  /health      - Health check")
    server.serve_forever()
