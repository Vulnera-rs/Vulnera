FROM rust:1.92-slim-bookworm

ARG USERNAME=vulnera
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get -y install --no-install-recommends \
        pkg-config \
        libssl-dev \
        libpq-dev \
        libclang-dev \
        cmake \
        build-essential \
        git \
        curl \
        wget \
        unzip \
        zsh \
        redis-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && chsh -s /bin/zsh $USERNAME

RUN cargo install cargo-chef --locked \
    && cargo install cargo-nextest --locked \
    && cargo install sqlx-cli --no-default-features --features postgres --locked \
    && cargo install just --locked

USER $USERNAME
