FROM golang:1.22

# Build system: go | Primary language: go
# Sanitizers: race detector

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      ripgrep gdb strace coreutils ca-certificates build-essential && \
    rm -rf /var/lib/apt/lists/*

ENV GOFLAGS="-mod=mod"

WORKDIR /workspace

# /scratch is mounted at runtime as a writable tmpfs
RUN mkdir -p /scratch
