# One image, five servers: the SERVER build arg picks which adapter runs.
FROM python:3.13-slim
ARG SERVER=menu
WORKDIR /app
COPY sdk/python /app/sdk/python
COPY registry/manifests /app/registry/manifests
COPY servers/${SERVER}/server.py /app/server.py
RUN pip install --no-cache-dir /app/sdk/python && useradd -r app
ENV VALKYRIE_REGISTRY_DIR=/app/registry/manifests PYTHONUNBUFFERED=1
USER app
CMD ["python", "/app/server.py"]
