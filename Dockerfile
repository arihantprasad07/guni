# Guni API — Production Dockerfile
# Uses Python 3.11 slim for small image size

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed by lxml
RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching — only reinstalls if requirements change)
COPY requirements.txt .

# Install Python dependencies
# Note: playwright browsers NOT installed — API doesn't need browser execution
RUN pip install --no-cache-dir \
    beautifulsoup4>=4.12.0 \
    lxml>=4.9.0 \
    fastapi>=0.110.0 \
    "uvicorn[standard]>=0.27.0" \
    pydantic>=2.0.0 \
    httpx>=0.27.0 \
    python-dotenv>=1.0.0

# Copy the entire project
COPY . .

# Install the guni package itself
RUN pip install --no-cache-dir setuptools wheel && pip install --no-cache-dir -e .

# Railway injects PORT env variable — uvicorn must bind to it
ENV PORT=8000
ENV GUNI_LOG_PATH=/tmp/guni_audit.log

# Expose port (documentation only — Railway uses PORT env var)
EXPOSE 8000

# Start the API server
# --host 0.0.0.0 is required in containers — never 127.0.0.1
CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT}
