#!/usr/bin/env python3
"""
Multi-instance test backend for Aenebris proxy load balancing
Accepts port number as command-line argument
"""

import json
import sys
from http.server import (
    HTTPServer,
    BaseHTTPRequestHandler,
)


class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                'status': 'healthy',
                'port': self.server.server_port
            }
            self.wfile.write(json.dumps(response).encode())
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        response = {
            'message':
            f'Hello from backend on port {self.server.server_port}!',
            'port': self.server.server_port,
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

        response = {
            'message': 'Received POST',
            'port': self.server.server_port,
            'path': self.path,
            'method': 'POST',
            'body_length': content_length
        }
        self.wfile.write(json.dumps(response, indent = 2).encode())

    def log_message(self, format, *args):
        print(f"[BACKEND:{self.server.server_port}] {format % args}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: test_backend_multi.py <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    server = HTTPServer(('localhost', port), TestHandler)
    print(f'Test backend running on http://localhost:{port}')
    server.serve_forever()
