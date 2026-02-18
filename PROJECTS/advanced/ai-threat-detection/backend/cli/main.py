"""
©AngelaMos | 2026
main.py
"""

import typer

app = typer.Typer(
    name="vigil",
    help="AngelusVigil — AI-powered threat detection engine",
    no_args_is_help=True,
)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Bind address"),
    port: int = typer.Option(8000, help="Bind port"),
    reload: bool = typer.Option(False, help="Enable auto-reload for development"),
) -> None:
    """
    Start the AngelusVigil API server.
    """
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def config() -> None:
    """
    Print the current configuration (secrets redacted).
    """
    from app.config import settings

    safe_fields = {}
    for key, value in settings.model_dump().items():
        if any(secret in key for secret in ("key", "password", "secret", "token")):
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
        "http://localhost:8000",
        help="Base URL of the running server",
    ),
) -> None:
    """
    Ping the running server's /health endpoint.
    """
    import httpx

    try:
        response = httpx.get(f"{url}/health", timeout=5.0)
        response.raise_for_status()
        data = response.json()
        typer.echo(f"  status: {data.get('status', 'unknown')}")
        typer.echo(f"  uptime: {data.get('uptime_seconds', 0):.0f}s")
        typer.echo(f"  pipeline: {'running' if data.get('pipeline_running') else 'stopped'}")
    except httpx.ConnectError:
        typer.echo("Error: cannot connect to server", err=True)
        raise typer.Exit(code=1) from None
    except httpx.HTTPStatusError as exc:
        typer.echo(f"Error: server returned {exc.response.status_code}", err=True)
        raise typer.Exit(code=1) from None


def _redact_url(url: str) -> str:
    """
    Replace the user:password portion of a database URL with ***:***.
    """
    if "://" not in url or "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    _, host_part = rest.rsplit("@", 1)
    return f"{scheme}://***:***@{host_part}"


if __name__ == "__main__":
    app()
