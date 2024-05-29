FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y cmake git wget build-essential && \
    rm -rf /var/cache/apt/archives /var/lib/apt/lists/* && \
    wget https://github.com/conan-io/conan/releases/download/1.64.1/conan-ubuntu-64.deb -O /tmp/conan.deb && \
    dpkg -i /tmp/conan.deb && \
    rm /tmp/conan.deb

ENTRYPOINT ["/bin/bash"]