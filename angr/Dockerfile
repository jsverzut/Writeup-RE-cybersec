FROM python:3.12-slim-bookworm AS builder

ARG ANGR_VERSION=9.2.223

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        pkg-config \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip setuptools wheel \
 && pip install "angr==${ANGR_VERSION}" \
                "claripy==${ANGR_VERSION}" \
                "bitstring==4.4.0" \
                "pycparser==3.0" \
                "unicorn==2.1.4"

FROM python:3.12-slim-bookworm

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY angr/solve.py /app/solve.py
COPY oldschool /app/oldschool

CMD ["python3", "solve.py"]
