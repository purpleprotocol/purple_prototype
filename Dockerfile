FROM alpine:edge

RUN apk add --no-cache \
    gcc \
    make \
    g++ \
    curl \
    cmake \
    rust \
    cargo \
    clang \
    linux-headers

RUN apk add 'openssl=1.1.1d-r2' 'openssl-dev=1.1.1d-r2'  --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/v3.8/main/

ADD . /opt/app
WORKDIR /opt/app

RUN cargo rustc --release -- -C target-feature=+crt-static -C codegen-units=1
FROM alpine:edge

COPY --from=0 /opt/app/target/release/purple /
EXPOSE 44034

ENV RUST_LOG info
ENTRYPOINT ["/purple"]