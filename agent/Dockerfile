FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 sentrynode && \
    mkdir -p /app && \
    chown -R sentrynode:sentrynode /app

WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=sentrynode:sentrynode . .

# Set env vars
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

USER sentrynode

CMD ["python", "-m", "collector.main"]
