FROM python:3.12-alpine
WORKDIR /app
COPY server.py transfer.py url_import.py authorization.py server_storage.py /app/
RUN addgroup -S uploader && adduser -S -G uploader uploader && mkdir -p /data/quarantine && chown uploader:uploader /data/quarantine
USER uploader
EXPOSE 8080
CMD ["python","-u","/app/server.py"]
