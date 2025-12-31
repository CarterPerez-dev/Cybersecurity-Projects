#!/usr/bin/env python3
"""
Simple test backend for Aenebris proxy
"""

import json
from http.server import (
    HTTPServer,
    BaseHTTPRequestHandler,
)


class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Health check endpoint
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {'status': 'healthy'}
            self.wfile.write(json.dumps(response).encode())
            return

        # Normal request
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        response = {
            'message': 'Hello from test backend!',
            'path': self.path,
            'method': 'GET'
        }
        self.wfile.write(json.dumps(response, indent = 2).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        try:
            body_json = json.loads(body.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            body_json = body.decode('utf-8', errors='replace')

        response = {
            'message': 'Received POST',
            'path': self.path,
            'method': 'POST',
            'body_length': content_length,
            'body_received': body_json
        }
        self.wfile.write(json.dumps(response, indent = 2).encode())

    def log_message(self, format, *args):
        print(f"[BACKEND] {format % args}")


if __name__ == '__main__':
    server = HTTPServer(('localhost', 8000), TestHandler)
    print('Test backend running on http://localhost:8000')
    server.serve_forever()
