FROM eclipse-temurin:21

# Build system: maven | Primary language: java

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      maven ripgrep ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# /scratch is mounted at runtime as a writable tmpfs
RUN mkdir -p /scratch
