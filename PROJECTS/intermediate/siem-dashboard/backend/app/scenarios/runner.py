"""
©AngelaMos | 2026
runner.py

Scenario playback engine

ScenarioThread plays back a Playbook in a daemon thread, applying
speed multiplier and 20% jitter to event delays. For each event it
normalizes, classifies, persists to MongoDB, and publishes to the log
Redis Stream. ScenarioRunner is a class-level singleton registry that
manages all active threads across start, stop, pause, resume, and
speed adjustment.

Key exports:
  ScenarioRunner - singleton manager for all active scenario threads
  ScenarioThread - daemon thread that plays back a single playbook

Connects to:
  config.py - reads SCENARIO_PLAYBOOK_DIR, LOG_STREAM_KEY
  core/streaming.py - calls publish_event after each event
  engine/normalizer.py - calls normalize
  engine/severity.py - calls classify
  models/LogEvent.py - calls LogEvent.create_event
  models/ScenarioRun.py - calls lifecycle methods
  scenarios/playbook.py - calls Playbook.load
  controllers/scenario_ctrl.py - calls ScenarioRunner methods
"""

import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from app.config import settings
from app.core.streaming import publish_event
from app.engine.normalizer import normalize
from app.engine.severity import classify
from app.models.LogEvent import LogEvent
from app.models.ScenarioRun import ScenarioRun
from app.scenarios.playbook import Playbook


logger = structlog.get_logger()

JITTER_FACTOR = 0.2


@dataclass
class ScenarioThread:
    """
    A daemon thread that plays back a single scenario playbook
    """
    run_id: str
    playbook: Playbook
    thread: threading.Thread = field(init = False)
    stop_event: threading.Event = field(default_factory = threading.Event)
    pause_event: threading.Event = field(default_factory = threading.Event)
    speed: float = 1.0

    def __post_init__(self) -> None:
        self.pause_event.set()
        self.thread = threading.Thread(
            target = self._run,
            daemon = True,
            name = f"scenario-{self.run_id}",
        )

    def start(self) -> None:
        """
        Start the playback thread
        """
        self.thread.start()

    def stop(self) -> None:
        """
        Signal the thread to stop
        """
        self.stop_event.set()
        self.pause_event.set()

    def pause(self) -> None:
        """
        Pause playback until resumed
        """
        self.pause_event.clear()

    def resume(self) -> None:
        """
        Resume paused playback
        """
        self.pause_event.set()

    def _run(self) -> None:
        """
        Iterate through playbook events with delay and jitter
        """
        try:
            run = ScenarioRun.get_by_id(self.run_id)

            for event in self.playbook.events:
                if self.stop_event.is_set():
                    break

                self.pause_event.wait()
                if self.stop_event.is_set():
                    break

                delay = event.delay_seconds / self.speed
                jitter = delay * JITTER_FACTOR
                actual_delay = max(0, delay + random.uniform(-jitter, jitter))  # noqa: S311
                time.sleep(actual_delay)

                if self.stop_event.is_set():
                    break

                self._emit_event(event, run)

            if self.stop_event.is_set():
                run.mark_stopped()
            else:
                run.mark_completed()
        except Exception:
            logger.exception("scenario_thread_error", run_id = self.run_id)
            try:
                run = ScenarioRun.get_by_id(self.run_id)
                run.mark_error(f"Thread crashed: check logs for run {self.run_id}")
            except Exception:
                logger.exception("scenario_error_update_failed", run_id = self.run_id)
        finally:
            ScenarioRunner.remove(self.run_id)

    def _emit_event(self, event: Any, run: ScenarioRun) -> None:
        """
        Normalize, persist, and publish a single playbook event
        """
        raw = {
            "source_type": event.source_type,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "dest_ip": event.dest_ip,
            "source_port": event.source_port,
            "dest_port": event.dest_port,
            "hostname": event.hostname,
            "username": event.username,
            "mitre_tactic": event.mitre_tactic,
            "mitre_technique": event.mitre_technique,
            "message": event.message,
            **event.extra,
        }
        raw = {k: v for k, v in raw.items() if v is not None}

        normalized = normalize(raw)
        severity = classify(normalized)

        log_event = LogEvent.create_event(
            **normalized,
            severity = severity,
            scenario_run_id = run.id,
            mitre_tactic = event.mitre_tactic,
            mitre_technique = event.mitre_technique,
        )

        publish_event(
            settings.LOG_STREAM_KEY,
            {
                "id": str(log_event.id),
                "timestamp": str(log_event.timestamp),
                "source_type": log_event.source_type,
                "severity": log_event.severity,
                "event_type": log_event.event_type,
                "source_ip": log_event.source_ip,
                "dest_ip": log_event.dest_ip,
                "hostname": log_event.hostname,
                "username": log_event.username,
                "scenario_run_id": str(run.id),
            },
        )

        run.increment_events()


class ScenarioRunner:
    """
    Singleton manager for active scenario threads
    """
    _active: dict[str, ScenarioThread] = {}  # noqa: RUF012
    _lock = threading.Lock()

    @classmethod
    def start(cls, scenario_filename: str) -> ScenarioRun:
        """
        Load a playbook and start a new scenario thread
        """
        path = Path(settings.SCENARIO_PLAYBOOK_DIR) / scenario_filename
        playbook = Playbook.load(path)
        run = ScenarioRun.start_run(playbook.name)

        thread = ScenarioThread(
            run_id = str(run.id),
            playbook = playbook,
        )

        with cls._lock:
            cls._active[str(run.id)] = thread

        thread.start()
        return run

    @classmethod
    def stop(cls, run_id: str) -> None:
        """
        Stop an active scenario thread
        """
        with cls._lock:
            thread = cls._active.get(run_id)
        if thread:
            thread.stop()
            run = ScenarioRun.get_by_id(run_id)
            run.mark_stopped()

    @classmethod
    def pause(cls, run_id: str) -> None:
        """
        Pause an active scenario thread
        """
        with cls._lock:
            thread = cls._active.get(run_id)
        if thread:
            thread.pause()
            run = ScenarioRun.get_by_id(run_id)
            run.mark_paused()

    @classmethod
    def resume(cls, run_id: str) -> None:
        """
        Resume a paused scenario thread
        """
        with cls._lock:
            thread = cls._active.get(run_id)
        if thread:
            thread.resume()
            run = ScenarioRun.get_by_id(run_id)
            run.mark_resumed()

    @classmethod
    def set_speed(cls, run_id: str, speed: float) -> None:
        """
        Adjust the playback speed of an active scenario
        """
        with cls._lock:
            thread = cls._active.get(run_id)
        if thread:
            thread.speed = speed
            run = ScenarioRun.get_by_id(run_id)
            run.set_speed(speed)

    @classmethod
    def remove(cls, run_id: str) -> None:
        """
        Remove a completed or stopped thread from the active map
        """
        with cls._lock:
            cls._active.pop(run_id, None)

    @classmethod
    def get_active_ids(cls) -> list[str]:
        """
        Return IDs of all currently active scenario threads
        """
        with cls._lock:
            return list(cls._active.keys())
