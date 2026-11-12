FROM python:3.12-slim-bookworm AS builder

ARG Z3_VERSION=4.13.0.0

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip setuptools wheel \
 && pip install "z3-solver==${Z3_VERSION}"

FROM python:3.12-slim-bookworm

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY keygen.py /app/keygen.py
COPY utils/buffer.bin /app/utils/buffer.bin
COPY utils/dword_1E180.bin /app/utils/dword_1E180.bin
COPY utils/dword_250E0.bin /app/utils/dword_250E0.bin
COPY utils/dword_25160.bin /app/utils/dword_25160.bin
COPY utils/flag_maker.py /app/utils/flag_maker.py

CMD ["python3", "keygen.py"]
