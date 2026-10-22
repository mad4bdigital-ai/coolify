FROM mcr.microsoft.com/playwright/python:v1.58.0-noble
WORKDIR /worker
COPY worker.py /worker/worker.py
RUN useradd -m -u 11001 browserworker && mkdir -p /browser-profile && chown 11001:11001 /browser-profile
USER 11001
EXPOSE 13871
CMD ["python", "/worker/worker.py"]
