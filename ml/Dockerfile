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


COPY ml_server/requirements.txt .


RUN python3.11 -m pip install --no-cache-dir -r requirements.txt


COPY proto /proto
RUN python3.11 -m grpc_tools.protoc \
    -I/proto \
    --python_out=/app \
    --grpc_python_out=/app \
    /proto/ml_service.proto


COPY ml_server/ .


ENV PYTHONUNBUFFERED=1
ENV GRPC_PORT=50051
ENV LLM_GUARD_DEVICE=cuda

EXPOSE 50051

CMD ["python3.11", "server.py"]
