FROM eclipse-temurin:21

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        maven ripgrep ca-certificates \
        python3 python3-pip valgrind ccache git ltrace && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages pyjwt requests cryptography pycryptodome

WORKDIR /workspace
RUN mkdir -p /scratch
