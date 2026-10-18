FROM ubuntu:24.04

LABEL maintainer="flare-re-mcp"
LABEL description="Containerized Multi-MCP Static Malware Analysis Suite (DIE, FLOSS, CAPA, Rizin, Radare2, Ghidra/PyGhidra)"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV CAPA_RULES_PATH=/opt/capa-rules
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    openjdk-21-jdk-headless \
    radare2 \
    rizin \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra 11.3 / 12.x Headless in /opt/ghidra
RUN mkdir -p /opt/ghidra /opt/capa-rules /workspace/samples
WORKDIR /workspace

COPY . /workspace/flare-re-mcp
WORKDIR /workspace/flare-re-mcp

RUN pip3 install --break-system-packages -e . yara-python && \
    python3 install.py --download-missing --skip-pip

ENTRYPOINT ["python3", "-m", "flare_re_mcp.orchestrator_qa"]
CMD ["--help"]
