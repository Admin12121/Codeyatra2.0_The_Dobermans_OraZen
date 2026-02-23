FROM nvidia/cuda:12.1.1-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

WORKDIR /app

RUN apt-get update && apt-get install -y \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3-pip \
    build-essential \
    protobuf-compiler \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1 \
    && rm -rf /var/lib/apt/lists/*

RUN python3.11 -m pip install --upgrade pip

COPY ml/requirement.txt /tmp/requirements.txt
RUN python3.11 -m pip install --no-cache-dir -r /tmp/requirements.txt

COPY ml/ml_service.proto /app/ml_service.proto
RUN python3.11 -m grpc_tools.protoc \
    -I/app \
    --python_out=/app \
    --grpc_python_out=/app \
    /app/ml_service.proto

RUN mkdir -p /app/scanners

COPY ml/server.py /app/server.py
COPY ml/ml_server/garak_scanner.py /app/scanners/garak_scanner.py
COPY ml/ml_server/llm_guard.py /app/scanners/llm_guard_scanner.py
RUN touch /app/scanners/__init__.py

ENV PYTHONUNBUFFERED=1
ENV GRPC_PORT=50051
ENV LLM_GUARD_DEVICE=cuda

EXPOSE 50051

CMD ["python3.11", "server.py"]
