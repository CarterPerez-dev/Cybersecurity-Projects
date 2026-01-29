#!/usr/bin/env python3
"""
WebSocket Echo Server for Aenebris testing
"""

import asyncio
import json
from datetime import datetime

try:
    import websockets
except ImportError:
    print("Install websockets: pip install websockets")
    exit(1)


async def echo_handler(websocket):
    client_addr = websocket.remote_address
    print(f"[WS] Client connected: {client_addr}")

    try:
        async for message in websocket:
            print(f"[WS] Received from {client_addr}: {message[:100]}...")

            if message == "ping":
                await websocket.send("pong")
            elif message == "time":
                await websocket.send(datetime.now().isoformat())
            elif message == "info":
                info = {
                    "server": "Aenebris WebSocket Test Server",
                    "client": str(client_addr),
                    "protocol": "WebSocket",
                    "timestamp": datetime.now().isoformat()
                }
                await websocket.send(json.dumps(info))
            else:
                response = {
                    "echo": message,
                    "length": len(message),
                    "timestamp": datetime.now().isoformat()
                }
                await websocket.send(json.dumps(response))

    except websockets.exceptions.ConnectionClosed as e:
        print(f"[WS] Client {client_addr} disconnected: {e.code} {e.reason}")


async def main():
    port = 8002
    async with websockets.serve(echo_handler, "localhost", port):
        print(f"WebSocket echo server running on ws://localhost:{port}")
        print("Commands: 'ping' -> 'pong', 'time' -> timestamp, 'info' -> server info")
        print("Other messages are echoed back as JSON")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
