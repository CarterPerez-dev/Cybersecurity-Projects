"""
Batch processing service for metadata operations.

This module provides handler-agnostic batch processing that works with any
MetadataHandler subclass (images now, PDF/Office docs in future).

Supports concurrent processing via ThreadPoolExecutor for efficient handling
of large batches (1000+ files).
"""

import logging
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from src.services.metadata_factory import MetadataFactory


log = logging.getLogger("metadata-scrubber")
console = Console()


@dataclass
class FileResult:
    """Result of processing a single file."""

    filepath: Path
    success: bool
    action: str  # "scrubbed", "skipped", "dry-run"
    output_path: Path | None = None
    error: str | None = None


@dataclass
class BatchSummary:
    """Aggregated statistics for batch processing."""

    total: int = 0
    success: int = 0
    skipped: int = 0
    failed: int = 0
    dry_run: bool = False
    output_dir: Path | None = None
    results: list[FileResult] = field(default_factory = list)


class BatchProcessor:
    """
    Handler-agnostic batch processor for metadata operations.

    Works with any MetadataHandler subclass via MetadataFactory.
    Supports dry-run mode, automatic duplicate suffix handling,
    and concurrent processing via ThreadPoolExecutor.
    """
    def __init__(
        self,
        output_dir: str | None = None,
        dry_run: bool = False,
        max_workers: int = 4,
    ):
        """
        Initialize the batch processor.

        Args:
            output_dir: Directory to save processed files. Defaults to "./scrubbed".
            dry_run: If True, preview what would be processed without writing files.
            max_workers: Maximum number of concurrent worker threads. Defaults to 4.
        """
        self.output_dir = Path(output_dir) if output_dir else Path("./scrubbed")
        self.dry_run = dry_run
        self.max_workers = max_workers
        self.results: list[FileResult] = []

        # Thread synchronization
        self._path_lock = threading.Lock()  # Protects unique path generation
        self._results_lock = threading.Lock()  # Protects results list

    def process_file(self, file: Path) -> FileResult:
        """
        Process a single file through the read→wipe→save pipeline.

        Uses MetadataFactory to get the appropriate handler, so this method
        automatically works with any file type that has a registered handler.

        Args:
            file: Path to the file to process.

        Returns:
            FileResult with success status and details.
        """
        output_path: Path | None = None  # Track reserved path for cleanup

        try:
            # Dry-run mode: just report what would happen
            if self.dry_run:
                # Verify the file can be handled (will raise if not)
                MetadataFactory.get_handler(str(file))
                output_path = self._get_unique_output_path(file, reserve = False)
                result = FileResult(
                    filepath = file,
                    success = True,
                    action = "dry-run",
                    output_path = output_path,
                )
                self._append_result(result)
                log.debug(f"[DRY-RUN] Would process: {file}")
                return result

            # Get handler from factory
            handler = MetadataFactory.get_handler(str(file))

            # Execute the read → wipe → save pipeline
            handler.read()
            handler.wipe()

            output_path = self._get_unique_output_path(file)
            handler.save(str(output_path))

            result = FileResult(
                filepath = file,
                success = True,
                action = "scrubbed",
                output_path = output_path,
            )
            self._append_result(result)
            if log.isEnabledFor(logging.DEBUG):
                # if verbose mode is enabled, log the Info
                log.info(f"✅ Scrubbed: {file.name} → {output_path}")
            return result

        except Exception as e:
            # Cleanup: remove empty placeholder file if reservation failed
            self._cleanup_reserved_path(output_path)

            result = FileResult(
                filepath = file,
                success = False,
                action = "skipped",
                error = str(e),
            )
            self._append_result(result)
            if log.isEnabledFor(logging.DEBUG):
                # if verbose mode is enabled, log the traceback
                log.warning(f"⚠️ Skipped {file.name}: {e}")
            return result

    def process_batch(
        self,
        files: Iterable[Path],
        progress_callback: Callable[[FileResult],
                                    None] | None = None,
    ) -> list[FileResult]:
        """
        Process multiple files concurrently using ThreadPoolExecutor.

        Args:
            files: Iterable of file paths to process.
            progress_callback: Optional callback called after each file completes.
                              Receives the FileResult for progress updates.

        Returns:
            List of FileResult objects for all processed files.
        """
        file_list = list(files)

        if not file_list:
            return self.results

        # Used ThreadPoolExecutor for I/O-bound concurrent processing
        with ThreadPoolExecutor(max_workers = self.max_workers) as executor:
            # Submit all files for processing
            future_to_file = {
                executor.submit(self.process_file,
                                file): file
                for file in file_list
            }

            # Collect results as they complete
            for future in as_completed(future_to_file):
                result = future.result()
                if progress_callback:
                    progress_callback(result)

        return self.results

    def process_batch_sequential(self, files: Iterable[Path]) -> list[FileResult]:
        """
        Process files sequentially (legacy behavior for debugging).

        Args:
            files: Iterable of file paths to process.

        Returns:
            List of FileResult objects for all processed files.
        """
        for file in files:
            self.process_file(file)
        return self.results

    def get_summary(self) -> BatchSummary:
        """
        Return aggregated statistics for all processed files.

        Returns:
            BatchSummary with counts and result details.
        """
        with self._results_lock:
            results_copy = list(self.results)

        summary = BatchSummary(
            total = len(results_copy),
            success = sum(
                1 for r in results_copy if r.success and r.action == "scrubbed"
            ),
            skipped = sum(1 for r in results_copy if not r.success),
            dry_run = self.dry_run,
            output_dir = self.output_dir,
            results = results_copy,
        )
        # Count dry-run as separate from success for clarity
        if self.dry_run:
            summary.success = sum(1 for r in results_copy if r.success)
        return summary

    def _append_result(self, result: FileResult) -> None:
        """Thread-safe append to results list."""
        with self._results_lock:
            self.results.append(result)

    def _cleanup_reserved_path(self, output_path: Path | None) -> None:
        """
        Remove empty placeholder file created during path reservation.

        Called when processing fails after _get_unique_output_path() reserved
        a path via touch(). Only removes files that are empty (0 bytes) to
        avoid deleting partially written data.

        Args:
            output_path: Path that was reserved, or None if not yet reserved.
        """
        if output_path is None:
            return

        try:
            if output_path.exists() and output_path.stat().st_size == 0:
                output_path.unlink()
                log.debug(f"Cleaned up empty placeholder: {output_path}")
        except OSError:
            # Best effort cleanup - don't fail if we can't delete
            pass

    def _get_unique_output_path(self, file: Path, reserve: bool = True) -> Path:
        """
        Generate unique output path with suffix (_1, _2) if file exists.

        Thread-safe: uses lock to prevent race conditions during concurrent processing.

        Args:
            file: Original file path.
            reserve: If True, create placeholder file to reserve the path.
                     Set to False for dry-run mode.

        Returns:
            Unique path in output directory that doesn't conflict with existing files.
        """
        with self._path_lock:
            # creates the destination directory if it doesn't exist
            self.output_dir.mkdir(parents = True, exist_ok = True)

            base_name = file.stem
            extension = file.suffix
            output_path = self.output_dir / f"processed_{base_name}{extension}"

            # If file exists, add incrementing suffix
            counter = 1
            while output_path.exists():
                output_path = (
                    self.output_dir / f"processed_{base_name}_{counter}{extension}"
                )
                counter += 1

            # Create empty placeholder to reserve the path (skip in dry-run)
            if reserve:
                output_path.touch()

            return output_path
