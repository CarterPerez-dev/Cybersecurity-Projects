"""
AngelaMos | 2026
router.py

Operator interface combining a WebSocket dashboard channel and REST beacon routes

The /ws/operator WebSocket sends the current beacon list on connect
and accepts submit_task messages from the operator. Three REST routes
cover beacon listing, single-beacon lookup, and task history. All
handlers share the registry, task manager, and ops manager from
app.state.

Key exports:
  ws_router - WebSocket router mounted at /ws/operator
  rest_router - REST routes for /beacons and /beacons/{id}

Connects to:
  beacon/registry.py - reads beacon list and active status
  beacon/tasking.py - submits tasks and fetches history
  core/models.py - uses CommandType, TaskRecord
  database.py - calls get_db()
  ops/manager.py - manages operator connections
"""

import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect

from app.beacon.registry import BeaconRegistry
from app.beacon.tasking import TaskManager
from app.core.models import CommandType, TaskRecord
from app.database import get_db
from app.ops.manager import OpsManager


logger = logging.getLogger(__name__)

ws_router = APIRouter()
rest_router = APIRouter()


@ws_router.websocket("/operator")
async def operator_websocket(ws: WebSocket) -> None:
    """
    WebSocket endpoint for operator dashboard connections
    """
    ops_manager: OpsManager = ws.app.state.ops_manager
    registry: BeaconRegistry = ws.app.state.registry
    task_manager: TaskManager = ws.app.state.task_manager

    await ops_manager.connect(ws)

    try:
        async with get_db() as db:
            beacons = await registry.get_all(db)

        beacon_list = []
        for b in beacons:
            record = b.model_dump()
            record["active"] = registry.is_active(b.id)
            beacon_list.append(record)

        await ws.send_text(
            json.dumps({
                "type": "beacon_list",
                "payload": beacon_list,
            })
        )

        while True:
            raw = await ws.receive_text()
            data = json.loads(raw)

            if data.get("type") == "submit_task":
                payload = data["payload"]
                task = TaskRecord(
                    id = str(uuid.uuid4()),
                    beacon_id = payload["beacon_id"],
                    command = CommandType(payload["command"]),
                    args = payload.get("args"),
                )

                async with get_db() as db:
                    await task_manager.submit(task, db)

                await ws.send_text(
                    json.dumps(
                        {
                            "type": "task_submitted",
                            "payload": {
                                "local_id": payload.get("local_id"),
                                "task_id": task.id,
                            },
                        }
                    )
                )

                logger.info(
                    "Task %s (%s) submitted for beacon %s",
                    task.id,
                    task.command,
                    task.beacon_id,
                )

    except WebSocketDisconnect:
        pass
    except json.JSONDecodeError:
        logger.warning("Invalid JSON from operator")
    finally:
        ops_manager.disconnect(ws)


@rest_router.get("/beacons")
async def list_beacons(request: Request) -> list[dict[str, Any]]:
    """
    List all known beacons with active connection status
    """
    registry: BeaconRegistry = request.app.state.registry
    async with get_db() as db:
        beacons = await registry.get_all(db)

    result = []
    for b in beacons:
        record = b.model_dump()
        record["active"] = registry.is_active(b.id)
        result.append(record)
    return result


@rest_router.get("/beacons/{beacon_id}")
async def get_beacon(request: Request, beacon_id: str) -> dict[str, Any]:
    """
    Retrieve a single beacon by ID with active status
    """
    registry: BeaconRegistry = request.app.state.registry
    async with get_db() as db:
        beacon = await registry.get_one(beacon_id, db)

    if beacon is None:
        raise HTTPException(status_code = 404, detail = "Beacon not found")

    record = beacon.model_dump()
    record["active"] = registry.is_active(beacon_id)
    return record


@rest_router.get("/beacons/{beacon_id}/tasks")
async def beacon_task_history(request: Request,
                              beacon_id: str) -> list[dict[str,
                                                           str | None]]:
    """
    Retrieve task history with results for a specific beacon
    """
    task_manager: TaskManager = request.app.state.task_manager
    async with get_db() as db:
        return await task_manager.get_history(beacon_id, db)
