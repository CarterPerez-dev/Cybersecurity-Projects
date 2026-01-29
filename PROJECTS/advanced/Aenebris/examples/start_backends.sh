#!/bin/bash
# Start multiple test backends for load balancing testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Kill any existing backends
pkill -f "test_backend_multi.py" || true

echo "Starting 3 test backends..."

# Start backend on port 8000
python3 "$SCRIPT_DIR/test_backend_multi.py" 8000 > /tmp/backend-8000.log 2>&1 &
echo "Backend 1 started on port 8000 (PID: $!)"

# Start backend on port 8001
python3 "$SCRIPT_DIR/test_backend_multi.py" 8001 > /tmp/backend-8001.log 2>&1 &
echo "Backend 2 started on port 8001 (PID: $!)"

# Start backend on port 8002
python3 "$SCRIPT_DIR/test_backend_multi.py" 8002 > /tmp/backend-8002.log 2>&1 &
echo "Backend 3 started on port 8002 (PID: $!)"

echo ""
echo "All backends started! Logs in /tmp/backend-*.log"
echo "Test health checks:"
echo "  curl http://localhost:8000/health"
echo "  curl http://localhost:8001/health"
echo "  curl http://localhost:8002/health"
