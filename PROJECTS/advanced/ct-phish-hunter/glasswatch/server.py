"""Minimal read-only dashboard over the findings database.

Deliberately stdlib-only (`http.server`, no Flask/FastAPI): this is a
local, single-user, read-only view of a SQLite file, and pulling in a
web framework for that would be more dependency than the job needs.

Security note: every value rendered here (`domain`, `reasons`) came out
of a certificate an attacker controlled. A phishing domain is exactly
the kind of string that might contain `<script>` if someone tries it, so
everything goes through `html.escape()` before it touches the response.
Skipping that step would turn a phishing *detector* into a stored-XSS
delivery mechanism, which would be a fairly embarrassing way for a
security tool to fail.
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from glasswatch.store import FindingsStore

PAGE_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>glasswatch</title>
<style>
  body {{ font-family: ui-monospace, monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 0.4rem 0.8rem; border-bottom: 1px solid #21262d; }}
  th {{ color: #8b949e; text-transform: uppercase; font-size: 0.75rem; }}
  .critical {{ color: #f85149; font-weight: bold; }}
  .high {{ color: #ffa657; }}
  .medium {{ color: #d29922; }}
  .low {{ color: #8b949e; }}
  .reasons {{ color: #6e7681; font-size: 0.85rem; }}
  .meta {{ color: #6e7681; margin-bottom: 1.5rem; }}
</style>
</head>
<body>
<h1>glasswatch findings</h1>
<p class="meta">{count} findings tracked &middot; refresh the page for live data &middot; <a href="/api/findings" style="color:#58a6ff">/api/findings</a></p>
<table>
<tr><th>Severity</th><th>Score</th><th>Domain</th><th>Brand</th><th>Seen</th><th>Reasons</th></tr>
{rows}
</table>
</body>
</html>
"""

ROW_TEMPLATE = """<tr>
<td class="{severity}">{severity}</td>
<td>{score}</td>
<td>{domain}</td>
<td>{brand}</td>
<td>{seen_count}&times;</td>
<td class="reasons">{reasons}</td>
</tr>"""


def _row_to_dict(row) -> dict:
    return {
        "domain": row["domain"],
        "brand": row["brand"],
        "score": row["score"],
        "severity": row["severity"],
        "reasons": row["reasons"].split(","),
        "log_url": row["log_url"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "seen_count": row["seen_count"],
    }


def _make_handler(db_path: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args) -> None:  # quieter default logging
            pass

        def do_GET(self) -> None:
            if self.path.startswith("/api/findings"):
                self._serve_json()
            elif self.path in ("/", ""):
                self._serve_html()
            else:
                self.send_error(404)

        def _serve_json(self) -> None:
            with FindingsStore(db_path) as store:
                rows = [_row_to_dict(r) for r in store.list_findings()]
            body = json.dumps(rows, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _serve_html(self) -> None:
            with FindingsStore(db_path) as store:
                rows = store.list_findings()

            rendered_rows = []
            for row in rows:
                rendered_rows.append(ROW_TEMPLATE.format(
                    severity=html.escape(row["severity"]),
                    score=row["score"],
                    domain=html.escape(row["domain"]),
                    brand=html.escape(row["brand"]),
                    seen_count=row["seen_count"],
                    reasons=html.escape(row["reasons"]),
                ))

            page = PAGE_TEMPLATE.format(
                count=len(rows),
                rows="\n".join(rendered_rows) or "<tr><td colspan=6>no findings yet</td></tr>",
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

    return Handler


def serve_dashboard(db_path: str, port: int = 8787, host: str = "127.0.0.1") -> None:
    handler = _make_handler(db_path)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"glasswatch dashboard on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
