FROM gitpod/workspace-full

RUN sudo apt-get update \
    && sudo apt-get install -y \
        apache2-bin \
        apache2-dev \
        bear \
        curl \
        gnutls-bin \
        libapr1-dev \
        libgnutls28-dev \
        openssl \
        pandoc \
        pkg-config \
        procps \
        python3-argcomplete \
        python3-yaml \
    && sudo rm -rf /var/lib/apt/lists/*

ENV CC=clang
