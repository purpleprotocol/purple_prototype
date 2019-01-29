FROM alpine:edge

RUN apk add --no-cache \
    gcc \
    make \
    g++ \
    curl \
    cmake \
    'rust=1.31.1-r1' \
    'cargo=1.31.1-r1' \
    linux-headers

RUN apk add 'openssl=1.0.2q-r0' 'openssl-dev=1.0.2q-r0'  --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/v3.8/main/

ADD . /opt/app
WORKDIR /opt/app

RUN cargo rustc --release -- -C target-feature=+crt-static -C codegen-units=16 # -Z thinlto
FROM alpine:edge

WORKDIR /opt/app
COPY --from=0 /opt/app/target/release/purple .

RUN apk update
RUN apk --no-cache --update add bash
RUN rm -rf /var/cache/apk/*

EXPOSE 44034

ADD run_release.sh .
RUN chmod +x run_release.sh