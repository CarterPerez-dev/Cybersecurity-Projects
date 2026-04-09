"""
©AngelaMos | 2026
main.py

Typer CLI application with serve, train, replay, config,
and health commands

serve launches uvicorn with configurable host/port/reload.
train loads CSIC 2010 dataset and/or synthetic data, runs
TrainingOrchestrator, exports ONNX models, and writes
metadata to the database via _write_metadata (creates an
async engine, calls save_model_metadata). replay sends
historical log lines in batches to a running server's
/ingest/batch endpoint via httpx. config prints all
settings with secrets redacted (_redact_url masks
credentials in database URLs). health pings /health and
displays status, uptime, and pipeline state

Connects to:
  app/config            - settings for serve defaults
  app/main              - uvicorn target "app.main:app"
  ml/orchestrator       - TrainingOrchestrator for train
  ml/data_loader        - load_csic_dataset for CSIC data
  ml/synthetic          - generate_mixed_dataset
  ml/metadata           - save_model_metadata
  api/ingest            - /ingest/batch for replay
"""

import asyncio
import dataclasses
from pathlib import Path

import typer

app = typer.Typer(
    name="vigil",
    help="AngelusVigil — AI-powered threat detection engine",
    no_args_is_help=True,
)

DEFAULT_MODEL_DIR = "data/models"
DEFAULT_EPOCHS = 100
DEFAULT_BATCH_SIZE = 256
DEFAULT_SYNTHETIC_NORMAL = 1000
DEFAULT_SYNTHETIC_ATTACK = 500
DEFAULT_EXPERIMENT_NAME = "angelusvigil-training"
DEFAULT_SERVER_URL = "http://localhost:8000"


async def _write_metadata(
    model_dir: Path,
    training_samples: int,
    metrics: dict[str, object],
    mlflow_run_id: str | None,
    threshold: float | None,
) -> None:
    """
    Persist training metadata to the database
    """
    from app.config import settings
    from ml.metadata import save_model_metadata
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    from app.models import model_metadata as _reg  # noqa: F401
    from sqlmodel import SQLModel

    engine = create_async_engine(settings.database_url)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        async with factory() as session:
            await save_model_metadata(
                session,
                model_dir=model_dir,
                training_samples=training_samples,
                metrics=metrics,
                mlflow_run_id=mlflow_run_id,
                threshold=threshold,
            )
    finally:
        await engine.dispose()


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Bind address"),
    port: int = typer.Option(8000, help="Bind port"),
    reload: bool = typer.Option(False,
                                help="Enable auto-reload for development"),
) -> None:
    """
    Start the AngelusVigil API server
    """
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def train(
    csic_dir: Path = typer.Option(
        None,
        help="Path to CSIC 2010 dataset directory",
    ),
    synthetic_normal: int = typer.Option(
        DEFAULT_SYNTHETIC_NORMAL,
        help="Number of synthetic normal samples",
    ),
    synthetic_attack: int = typer.Option(
        DEFAULT_SYNTHETIC_ATTACK,
        help="Number of synthetic attack samples",
    ),
    output_dir: Path = typer.Option(
        DEFAULT_MODEL_DIR,
        help="Directory to save ONNX models",
    ),
    epochs: int = typer.Option(
        DEFAULT_EPOCHS,
        help="Autoencoder training epochs",
    ),
    batch_size: int = typer.Option(
        DEFAULT_BATCH_SIZE,
        help="Training batch size",
    ),
    experiment_name: str = typer.Option(
        DEFAULT_EXPERIMENT_NAME,
        help="MLflow experiment name",
    ),
) -> None:
    """
    Train all ML models and export to ONNX
    """
    import numpy as np

    from ml.orchestrator import TrainingOrchestrator

    X_parts: list[np.ndarray] = []
    y_parts: list[np.ndarray] = []

    if csic_dir is not None:
        if not csic_dir.exists():
            typer.echo(
                f"Error: CSIC directory not found"
                f" at {csic_dir}",
                err=True,
            )
            raise typer.Exit(code=1)

        from ml.data_loader import load_csic_dataset, load_csic_normal

        normal_path = csic_dir / "normalTrafficTraining.txt"
        normal_test_path = csic_dir / "normalTrafficTest.txt"
        attack_path = csic_dir / "anomalousTrafficTest.txt"
        typer.echo(f"Loading CSIC data from {csic_dir}")
        X_csic, y_csic = load_csic_dataset(
            normal_path, attack_path
        )
        X_parts.append(X_csic)
        y_parts.append(y_csic)
        typer.echo(
            f"  CSIC: {len(X_csic)} samples"
        )

        if normal_test_path.exists():
            X_extra, y_extra = load_csic_normal(normal_test_path)
            X_parts.append(X_extra)
            y_parts.append(y_extra)
            typer.echo(
                f"  CSIC normal test: {len(X_extra)} samples"
            )

    if synthetic_normal > 0 or synthetic_attack > 0:
        from ml.synthetic import generate_mixed_dataset

        typer.echo(
            f"Generating synthetic data:"
            f" {synthetic_normal} normal,"
            f" {synthetic_attack} attack"
        )
        X_syn, y_syn = generate_mixed_dataset(
            synthetic_normal, synthetic_attack
        )
        X_parts.append(X_syn)
        y_parts.append(y_syn)

    if not X_parts:
        typer.echo(
            "Error: no data sources specified",
            err=True,
        )
        raise typer.Exit(code=1)

    X = np.vstack(X_parts)
    y = np.concatenate(y_parts)
    typer.echo(
        f"Total: {len(X)} samples"
        f" ({int(np.sum(y == 0))} normal,"
        f" {int(np.sum(y == 1))} attack)"
    )

    orch = TrainingOrchestrator(
        output_dir=Path(output_dir),
        experiment_name=experiment_name,
        epochs=epochs,
        batch_size=batch_size,
    )
    result = orch.run(X, y)

    try:
        metrics: dict[str, object] = (
            dataclasses.asdict(result.ensemble_metrics)
            if result.ensemble_metrics else {}
        )
        asyncio.run(_write_metadata(
            Path(output_dir),
            int(len(X)),
            metrics,
            result.mlflow_run_id,
            result.ae_metrics.get("ae_threshold"),
        ))
        typer.echo("  Model metadata saved to database")
    except Exception as exc:
        typer.echo(
            f"  Warning: could not save metadata to DB: {exc}",
            err=True,
        )

    typer.echo(f"Models exported to {output_dir}")
    if result.ensemble_metrics is not None:
        typer.echo(
            f"  Ensemble F1:"
            f" {result.ensemble_metrics.f1:.4f}"
        )
        typer.echo(
            f"  Ensemble PR-AUC:"
            f" {result.ensemble_metrics.pr_auc:.4f}"
        )
    typer.echo(
        f"  Passed gates: {result.passed_gates}"
    )

    if not result.passed_gates:
        raise typer.Exit(code=1)


@app.command()
def replay(
        log_file: Path = typer.Option(...,
                                      help="Path to nginx access log file"),
        url: str = typer.Option(
            DEFAULT_SERVER_URL,
            help="Running server URL to send logs to",
        ),
        batch_size: int = typer.Option(100, help="Lines per batch"),
) -> None:
    """
    Replay historical log lines through the pipeline
    """
    import httpx

    if not log_file.exists():
        typer.echo(
            f"Error: log file not found at {log_file}",
            err=True,
        )
        raise typer.Exit(code=1)

    lines = log_file.read_text().strip().splitlines()
    typer.echo(f"Replaying {len(lines)} lines to {url}")

    sent = 0
    with httpx.Client(timeout=30.0) as client:
        for i in range(0, len(lines), batch_size):
            batch = lines[i:i + batch_size]
            response = client.post(
                f"{url}/ingest/batch",
                json={"lines": batch},
            )
            if response.status_code == 200:
                sent += len(batch)
            else:
                typer.echo(
                    f"  Batch {i} failed: {response.status_code}",
                    err=True,
                )

    typer.echo(f"Replayed {sent}/{len(lines)} lines")


@app.command()
def config() -> None:
    """
    Print the current configuration (secrets redacted)
    """
    from app.config import settings

    safe_fields = {}
    for key, value in settings.model_dump().items():
        if any(secret in key for secret in (
                "key",
                "password",
                "secret",
                "token",
        )):
            safe_fields[key] = "***REDACTED***"
        elif "url" in key and "@" in str(value):
            safe_fields[key] = _redact_url(str(value))
        else:
            safe_fields[key] = value

    for key, value in sorted(safe_fields.items()):
        typer.echo(f"  {key}: {value}")


@app.command()
def health(
    url: str = typer.Option(
        DEFAULT_SERVER_URL,
        help="Base URL of the running server",
    ),
) -> None:
    """
    Ping the running server's /health endpoint
    """
    import httpx

    try:
        response = httpx.get(f"{url}/health", timeout=5.0)
        response.raise_for_status()
        data = response.json()
        typer.echo(f"  status: {data.get('status', 'unknown')}")
        typer.echo(f"  uptime: {data.get('uptime_seconds', 0):.0f}s")
        typer.echo(
            f"  pipeline: {'running' if data.get('pipeline_running') else 'stopped'}"
        )
    except httpx.ConnectError:
        typer.echo("Error: cannot connect to server", err=True)
        raise typer.Exit(code=1) from None
    except httpx.HTTPStatusError as exc:
        typer.echo(
            f"Error: server returned {exc.response.status_code}",
            err=True,
        )
        raise typer.Exit(code=1) from None


def _redact_url(url: str) -> str:
    """
    Replace the user:password portion of a database
    URL with ***:***
    """
    if "://" not in url or "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    _, host_part = rest.rsplit("@", 1)
    return f"{scheme}://***:***@{host_part}"


if __name__ == "__main__":
    app()
