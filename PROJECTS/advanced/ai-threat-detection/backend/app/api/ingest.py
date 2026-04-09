"""
©AngelaMos | 2026
ingest.py

Batch log ingestion endpoint for pushing raw log lines
into the detection pipeline

POST /ingest/batch accepts a BatchIngestRequest (list of
raw log line strings), pushes each into the pipeline's
raw_queue via put_nowait, stops on QueueFull, and returns
the count of successfully queued lines. Protected by
require_api_key dependency

Connects to:
  deps.py              - require_api_key
  core/ingestion/
    pipeline.py        - pipeline.raw_queue
  factory.py           - app.state.pipeline
"""

import asyncio

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.api.deps import require_api_key

router = APIRouter(prefix="/ingest", tags=["ingest"])


class BatchIngestRequest(BaseModel):
    """
    Payload for bulk log line ingestion
    """

    lines: list[str]


@router.post("/batch", status_code=200, dependencies=[Depends(require_api_key)])
async def ingest_batch(
    body: BatchIngestRequest,
    request: Request,
) -> dict[str, int]:
    """
    Push a batch of raw log lines into the pipeline queue
    """
    pipeline = getattr(request.app.state, "pipeline", None)
    if pipeline is None:
        return {"queued": 0}

    queued = 0
    for line in body.lines:
        try:
            pipeline.raw_queue.put_nowait(line)
            queued += 1
        except asyncio.QueueFull:
            break

    return {"queued": queued}
