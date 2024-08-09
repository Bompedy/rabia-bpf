FROM ubuntu:22.04

USER root

RUN apt-get update && apt-get install -y \
    curl \
    iproute2 \
    iputils-ping \
    net-tools \
    git \
    clang-15 \
    make \
    build-essential \
    linux-headers-generic \
    libbpf-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    nlohmann-json3-dev

RUN ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm && git clone --recurse-submodules https://github.com/libbpf/bpftool.git
WORKDIR /bpftool/src
RUN make && make install && cp /bpftool/src/bpftool /usr/local/bin/

WORKDIR /app
COPY src /app/src
COPY Makefile /app/

ARG BUILD_TIME
ENV BUILD_TIME=${BUILD_TIME}
CMD ["bash", "-c", "make build"]