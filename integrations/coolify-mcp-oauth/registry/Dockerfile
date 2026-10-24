FROM python:3.12-alpine
WORKDIR /app
COPY server.py /app/server.py
RUN addgroup -S registry && adduser -S -G registry registry
USER registry
EXPOSE 8080
CMD ["python","-u","/app/server.py"]
