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
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Install the guni package itself
RUN pip install --no-cache-dir setuptools wheel && pip install --no-cache-dir -e .

# Railway injects PORT env variable — uvicorn must bind to it
ENV PORT=8000
ENV GUNI_LOG_PATH=/tmp/guni_audit.log

# Expose port (documentation only — Railway uses PORT env var)
EXPOSE 8000

# Start the API server using Python to read PORT env var
CMD ["sh", "-c", "gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT:-8000}"]
