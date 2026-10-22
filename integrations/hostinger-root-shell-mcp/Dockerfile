FROM python:3.12-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "mcp>=1.12,<2.0"
WORKDIR /app
COPY server.py registry.py providers.py hostinger_gateway.py hostinger_api.py browser_bridge.py /app/
COPY infrastructure-registry.example.json /app/infrastructure-registry.json
EXPOSE 8000
CMD ["python", "/app/server.py"]
