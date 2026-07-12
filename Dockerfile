# syntax=docker/dockerfile:1
FROM alpine:3.24.1 AS builder

RUN apk add --no-cache musl-dev libgcc

ADD https://github.com/laputa-systems/llvm-prebuilt-musl/releases/download/llvm-musl-22.1.8/clang+llvm-22.1.8-x86_64-linux-musl.tar.xz /tmp/llvm.tar.xz
RUN mkdir -p /opt/llvm-musl \
    && tar xf /tmp/llvm.tar.xz -C /opt/llvm-musl --strip-components=1 \
    && rm /tmp/llvm.tar.xz

ADD https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-musl/rustup-init /rustup-init
RUN chmod +x /rustup-init \
    && /rustup-init -y --default-toolchain none \
    && rm /rustup-init

ENV PATH="/opt/llvm-musl/bin:/root/.cargo/bin:$PATH" \
    CC="/opt/llvm-musl/bin/clang" \
    AR="/opt/llvm-musl/bin/llvm-ar" \
    RANLIB="/opt/llvm-musl/bin/llvm-ranlib" \
    CC_X86_64_UNKNOWN_LINUX_MUSL="/opt/llvm-musl/bin/clang" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="rust-lld" \
    CFLAGS_x86_64_unknown_linux_musl="--target=x86_64-unknown-linux-musl -I/usr/include"

RUN rustup toolchain install nightly-2026-04-20 \
    --target x86_64-unknown-linux-musl

# Host proc-macro crates link dynamically while Cargo is building. The musl
# rustup sysroot does not always expose the Alpine libc and libgcc_s names
# that rust-lld searches for, so install stable symlinks in the host target
# libdir.
RUN host_libdir="$(rustc --print target-libdir)" \
    && ln -sf /usr/lib/libgcc_s.so.1 "${host_libdir}/libgcc_s.so" \
    && ln -sf /usr/lib/libgcc_s.so.1 "${host_libdir}/libgcc_s.so.1" \
    && ln -sf /usr/lib/libc.so "${host_libdir}/libc.so"

WORKDIR /build
COPY . .

RUN cargo build --locked --bins --target x86_64-unknown-linux-musl --release

FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/laputa-mirror /
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/laputa-mirror-publish /
