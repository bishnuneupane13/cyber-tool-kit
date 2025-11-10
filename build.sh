#!/bin/bash
set -e

echo "🔨 Building Cyber Tool Kit for Render..."
echo ""

echo "📦 Installing Node dependencies..."
cd frontend
npm install --omit=dev
echo "✅ Node dependencies installed"
echo ""

echo "🏗️  Building frontend with Vite..."
npm run build
echo "✅ Frontend built successfully"
cd ..
echo ""

echo "🐍 Installing Python dependencies..."
# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
  echo "📦 Creating virtual environment..."
  python3 -m venv venv
fi

# Determine the correct pip/python paths based on OS
if [ -f "venv/Scripts/pip" ]; then
  # Windows Git Bash path
  VENV_PIP="venv/Scripts/pip"
  VENV_PYTHON="venv/Scripts/python"
elif [ -f "venv/bin/pip" ]; then
  # Unix/Linux/macOS path
  VENV_PIP="venv/bin/pip"
  VENV_PYTHON="venv/bin/python"
else
  echo "⚠️  Could not find venv. Using system pip."
  VENV_PIP="pip"
  VENV_PYTHON="python3"
fi

# Install dependencies using venv pip
$VENV_PIP install --upgrade pip
$VENV_PIP install --no-cache-dir -r requirements.txt
$VENV_PIP install --no-cache-dir gunicorn
echo "✅ Python dependencies installed"
echo ""

echo "🎉 Build complete! App ready for Render."
