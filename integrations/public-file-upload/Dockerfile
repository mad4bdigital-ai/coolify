FROM python:3.12-alpine
WORKDIR /app
COPY server.py /app/server.py
RUN addgroup -S uploader && adduser -S -G uploader uploader && mkdir -p /data/quarantine && chown -R uploader:uploader /data
USER uploader
EXPOSE 8080
CMD ["python", "-u", "/app/server.py"]
