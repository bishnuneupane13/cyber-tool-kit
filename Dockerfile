# Multi-stage Dockerfile
# Stage 1: Build frontend
FROM node:18-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --silent
COPY frontend/ .
RUN npm run build

# Stage 2: Python runtime with native tools
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system packages required for native tools (nmap, masscan) and building wheels
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc libpcap-dev nmap masscan ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ ./backend

# Copy built frontend from previous stage
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

EXPOSE 8000

# Use shell form so PORT env var can be respected if provided
CMD ["sh","-c","gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} backend.app:app"]
