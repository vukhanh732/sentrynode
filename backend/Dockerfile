FROM python:3.11-slim AS builder
WORKDIR /tmp
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim
RUN useradd -m -u 1000 sentrynode && mkdir -p /app && chown -R sentrynode:sentrynode /app
WORKDIR /app
COPY --from=builder /root/.local /home/sentrynode/.local
COPY --chown=sentrynode:sentrynode . .
ENV PATH=/home/sentrynode/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER sentrynode
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
