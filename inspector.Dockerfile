FROM python:3.13-slim
WORKDIR /app
COPY safe_fetch.py inspection_worker.py ./
USER 65534:65534
ENTRYPOINT ["python", "-B", "inspection_worker.py"]
