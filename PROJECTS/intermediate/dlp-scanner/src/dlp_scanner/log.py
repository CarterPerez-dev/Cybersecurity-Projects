"""
©AngelaMos | 2026
log.py
"""


import logging
import sys
from typing import Any

import orjson
import structlog


def _orjson_serializer(
    data: Any,
    **_kwargs: Any,
) -> str:
    """
    Serialize log data using orjson for performance
    """
    return orjson.dumps(data).decode("utf-8")


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
    log_file: str = "",
) -> None:
    """
    Set up structlog with stdlib integration
    """
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt = "iso"),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
    ]

    if json_output:
        renderer: structlog.types.Processor = (
            structlog.processors.JSONRenderer(
                serializer = _orjson_serializer
            )
        )
    else:
        renderer = structlog.dev.ConsoleRenderer(colors = True)

    structlog.configure(
        processors = [
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory = structlog.stdlib.LoggerFactory(),
        wrapper_class = structlog.stdlib.BoundLogger,
        cache_logger_on_first_use = True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain = shared_processors,
        processors = [
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler: logging.Handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, level.upper()))

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
