# Generic Dockerfile for CTF Challenges
# Supports both Python-based and binary challenges

FROM python:3.11-slim

# Install system dependencies for binary challenges
RUN apt-get update && apt-get install -y \
    gcc \
    gdb \
    binutils \
    file \
    xxd \
    binwalk \
    exiftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

# Copy requirements first for caching
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Default command - can be overridden
CMD ["python3", "-c", "print('CTF Challenge Container Ready')"]
