FROM ghcr.io/tpm2-software/ubuntu-18.04:latest

ENV PKG_CONFIG_PATH /usr/local/lib/pkgconfig

# Download and install TSS 2.0
RUN git clone https://github.com/tpm2-software/tpm2-tss.git --branch 2.3.3
RUN cd tpm2-tss \
	&& ./bootstrap \
	&& ./configure \
	&& make -j$(nproc) \
	&& make install \
	&& ldconfig

# Download and install TPM2 tools
RUN git clone https://github.com/tpm2-software/tpm2-tools.git --branch 4.1
RUN cd tpm2-tools \
	&& ./bootstrap \
	&& ./configure --enable-unit \
	&& make install

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN apt-get update -y -qq && \
    apt-get install --assume-yes --no-install-recommends \
        ca-certificates \
        clang \
        emacs \
        libclang-dev \
        libsofthsm2 \
        libsqlite3-dev \
        libssl-dev \
        nettle-dev \
        make \
        org-mode \
        pkg-config \
        && \
    apt-get clean

RUN cargo install sequoia-sq

COPY Cargo.toml Cargo.lock /app/
COPY src /app/src
WORKDIR /app

RUN cargo build

COPY README.org /app/

RUN emacs -Q --batch --eval " \
    (progn \
      (require 'ob-tangle) \
      (dolist (file command-line-args-left) \
        (with-current-buffer (find-file-noselect file) \
          (org-babel-tangle))))" README.org

RUN chmod +x README.sh

RUN ./README.sh

RUN cargo test

RUN cargo clippy -- -D warnings
