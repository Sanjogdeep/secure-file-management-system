#!/usr/bin/env bash
set -e
echo "🔒 Starting SecureFMS..."

# Create storage directory
mkdir -p backend/storage

# Start backend
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo "✅ Backend running on http://localhost:8000"
echo "📖 API Docs: http://localhost:8000/api/docs"

# Start frontend (simple HTTP server)
cd ../frontend
python3 -m http.server 3000 &
FRONTEND_PID=$!
echo "✅ Frontend running on http://localhost:3000"
echo ""
echo "🎯 Default admin credentials: admin / Admin@12345"
echo ""
echo "Press Ctrl+C to stop both servers."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
wait
