"""
©AngelaMos | 2026
app.py

Minimal FastAPI target application for generating nginx
access logs during development

Exposes realistic REST endpoints that the simulate.py
traffic generator hits through the nginx reverse proxy:
/ (HTML landing), /health, /api/users (list and by ID),
/api/login (POST returning a fake JWT), /api/search with
query parameter, /api/products (list and by ID),
/api/checkout (POST), /admin and /admin/dashboard (403
forbidden), and /static/{path} (404). Designed to produce
diverse nginx combined-format log lines for testing the
ingestion pipeline and rule engine

Connects to:
  dev-log/nginx.conf   - proxied behind nginx
  dev-log/simulate.py  - traffic generator targets these
                         endpoints
  dev-log/compose.yml  - containerized as vigil-devlog-app
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="DevLog Target App")

USERS = [
    {"id": 1, "name": "alice", "email": "alice@example.com", "role": "admin"},
    {"id": 2, "name": "bob", "email": "bob@example.com", "role": "user"},
    {"id": 3, "name": "carol", "email": "carol@example.com", "role": "user"},
]

PRODUCTS = [
    {"id": 1, "name": "Widget", "price": 29.99},
    {"id": 2, "name": "Gadget", "price": 49.99},
    {"id": 3, "name": "Doohickey", "price": 9.99},
]


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return "<html><body><h1>DevLog Target</h1></body></html>"


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/api/users")
async def list_users() -> list[dict[str, object]]:
    return USERS


@app.get("/api/users/{user_id}")
async def get_user(user_id: int) -> JSONResponse:
    for u in USERS:
        if u["id"] == user_id:
            return JSONResponse(u)
    return JSONResponse({"error": "not found"}, status_code=404)


@app.post("/api/login")
async def login(request: Request) -> JSONResponse:
    return JSONResponse({"token": "eyJhbGciOiJIUzI1NiJ9.fake.token"})


@app.get("/api/search")
async def search(q: str = "") -> dict[str, object]:
    return {"query": q, "results": [], "total": 0}


@app.get("/api/products")
async def list_products() -> list[dict[str, object]]:
    return PRODUCTS


@app.get("/api/products/{product_id}")
async def get_product(product_id: int) -> JSONResponse:
    for p in PRODUCTS:
        if p["id"] == product_id:
            return JSONResponse(p)
    return JSONResponse({"error": "not found"}, status_code=404)


@app.post("/api/checkout")
async def checkout() -> dict[str, object]:
    return {"order_id": "ORD-12345", "status": "confirmed"}


@app.get("/admin")
async def admin_panel() -> JSONResponse:
    return JSONResponse({"error": "forbidden"}, status_code=403)


@app.get("/admin/dashboard")
async def admin_dashboard() -> JSONResponse:
    return JSONResponse({"error": "forbidden"}, status_code=403)


@app.get("/static/{path:path}")
async def static_files(path: str) -> JSONResponse:
    return JSONResponse({"error": "not found"}, status_code=404)
