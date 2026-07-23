FROM gcc:12-bullseye

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        ripgrep gdb strace ltrace coreutils ca-certificates build-essential cmake \
        python3 python3-pip valgrind ccache git && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install pyjwt requests cryptography pycryptodome

WORKDIR /workspace
RUN mkdir -p /scratch
