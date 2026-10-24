FROM python:3.12-alpine
WORKDIR /app
COPY authz_service.py /app/
RUN addgroup -S authz && adduser -S -G authz authz
USER authz
EXPOSE 8080
CMD ["python","-u","/app/authz_service.py"]
