#!/usr/bin/env python3
"""
Test client for WebSocket and SSE through Aenebris proxy
"""

import asyncio
import sys
import json

try:
    import websockets
except ImportError:
    print("Install websockets: pip install websockets")
    websockets = None

try:
    import httpx
except ImportError:
    print("Install httpx: pip install httpx")
    httpx = None


async def test_websocket(host="localhost", port=8081):
    if websockets is None:
        print("SKIP: websockets not installed")
        return False

    uri = f"ws://{host}:{port}/ws"
    print(f"\n[TEST] WebSocket: {uri}")

    try:
        async with websockets.connect(uri, extra_headers={"Host": "ws.localhost"}) as ws:
            print("[OK] WebSocket connected")

            await ws.send("ping")
            response = await ws.recv()
            assert response == "pong", f"Expected 'pong', got '{response}'"
            print(f"[OK] ping -> {response}")

            await ws.send("Hello Aenebris!")
            response = await ws.recv()
            data = json.loads(response)
            assert data["echo"] == "Hello Aenebris!"
            print(f"[OK] echo -> {data}")

            await ws.send("time")
            response = await ws.recv()
            print(f"[OK] time -> {response}")

            print("[PASS] WebSocket test passed!")
            return True

    except Exception as e:
        print(f"[FAIL] WebSocket error: {e}")
        return False


async def test_sse(host="localhost", port=8081):
    if httpx is None:
        print("SKIP: httpx not installed")
        return False

    url = f"http://{host}:{port}/events"
    print(f"\n[TEST] SSE: {url}")

    try:
        async with httpx.AsyncClient() as client:
            async with client.stream("GET", url, headers={"Host": "sse.localhost"}) as response:
                print(f"[OK] SSE connected, status: {response.status_code}")
                print(f"[OK] Content-Type: {response.headers.get('content-type')}")

                count = 0
                async for line in response.aiter_lines():
                    if line.startswith("data:"):
                        data = json.loads(line[5:].strip())
                        print(f"[OK] Event: {data}")
                        count += 1
                        if count >= 3:
                            break

                print("[PASS] SSE test passed!")
                return True

    except Exception as e:
        print(f"[FAIL] SSE error: {e}")
        return False


async def test_both_simultaneously(host="localhost", port=8081):
    print("\n[TEST] Running WebSocket + SSE simultaneously...")

    ws_task = asyncio.create_task(test_websocket(host, port))
    sse_task = asyncio.create_task(test_sse(host, port))

    ws_ok, sse_ok = await asyncio.gather(ws_task, sse_task, return_exceptions=True)

    if isinstance(ws_ok, Exception):
        print(f"[FAIL] WebSocket: {ws_ok}")
        ws_ok = False
    if isinstance(sse_ok, Exception):
        print(f"[FAIL] SSE: {sse_ok}")
        sse_ok = False

    if ws_ok and sse_ok:
        print("\n" + "=" * 50)
        print("[SUCCESS] Both WebSocket AND SSE work simultaneously!")
        print("          nginx's conflict has been SOLVED!")
        print("=" * 50)
        return True
    else:
        print("\n[PARTIAL] Some tests failed")
        return False


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8081

    print("=" * 50)
    print("Aenebris WebSocket + SSE Test Suite")
    print("=" * 50)
    print(f"Target: {host}:{port}")

    asyncio.run(test_both_simultaneously(host, port))
