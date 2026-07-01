# STEP1: BUILD BACKEND FROM LOCAL FORK SOURCE
# The previous builder_prepare stage cloned upstream mickael-kerjean/filestash:master
# at build time, which silently bypassed every local fork commit (auto_login,
# editor max size, credential-merge gate). We COPY the build context instead, so
# whatever commit is checked out locally is what ships in the image.
FROM golang:1.26-trixie AS builder_backend
ARG FORK_SHA=unknown
ENV BUILD_REF=${FORK_SHA}
WORKDIR /home/filestash/
COPY . .
RUN apt-get update > /dev/null && \
    apt-get install -y curl make > /dev/null 2>&1 && \
    apt-get install -y libjpeg-dev libtiff-dev libpng-dev libwebp-dev libraw-dev libheif-dev libgif-dev libvips-dev > /dev/null 2>&1 && \
    make init && \
    make build && \
    mkdir -p ./dist/data/state/config/ && \
    cp config/config.json ./dist/data/state/config/config.json

# STEP3: BUILD PROD IMAGE
FROM debian:stable-slim
ARG FORK_SHA=unknown
LABEL org.opencontainers.image.revision="${FORK_SHA}"
WORKDIR /app/
COPY --from=builder_backend /home/filestash/dist/ .
RUN apt-get update > /dev/null && \
    apt-get install -y --no-install-recommends apt-utils && \
    apt-get upgrade -y && \
    apt-get install -y ca-certificates curl ffmpeg libjpeg-dev libtiff-dev libpng-dev libwebp-dev libraw-dev libheif-dev libgif-dev && \
    useradd filestash && \
    chown -R filestash:filestash /app/ && \
    find /app/data/ -type d -exec chmod 770 {} \; && \
    find /app/data/ -type f -exec chmod 760 {} \; && \
    chmod 730 /app/filestash && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/*

USER filestash
CMD ["/app/filestash"]
EXPOSE 8334