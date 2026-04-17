# Extends the base gaiax-opa image with Python for cli_exec scripts.
# The main Dockerfile stays free of Python; add or remove this layer
# depending on whether your cli_exec commands require it.
ARG BUILD_TAGS="gaiax_ovc grpc danube file_logger external_pdp cli_exec"

FROM golang:1.26-alpine AS builder
RUN apk update && apk add --no-cache git tzdata build-base
ARG BUILDPATH=/go/src/github.com/Posedio/gaiax-opa
ENV USER=pos UID=60000 GROUP=posedio GID=50000
RUN adduser --disabled-password --gecos "" --home "$(pwd)" --no-create-home --uid "$UID" "$USER"
RUN addgroup -g "$GID" "$GROUP" && addgroup "$USER" "$GROUP"
WORKDIR ${BUILDPATH}
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY internal/ internal/
ARG BUILD_TAGS
RUN go build --tags="${BUILD_TAGS}" -v -o gaiax-opa ./cmd/

FROM alpine
LABEL authors="Philipp Seifert-Kehrer,Stefan Dumss"
ENV USER=pos GROUP=posedio
ARG BUILDPATH=/go/src/github.com/Posedio/gaiax-opa

RUN apk add --no-cache python3

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder ${BUILDPATH}/gaiax-opa /usr/local/bin/gaiax-opa

RUN mkdir -p /policies && \
    mkdir -p /etc/gaiax-opa && \
    mkdir -p /run/secrets && \
    mkdir -p /scripts && \
    chown -R $USER:$GROUP /policies && \
    chown root:$GROUP /etc/gaiax-opa && chmod 750 /etc/gaiax-opa && \
    chown root:$GROUP /run/secrets && chmod 750 /run/secrets && \
    chown root:$GROUP /scripts && chmod 750 /scripts && \
    chown root:root /usr/local/bin/gaiax-opa && \
    chmod 755 /usr/local/bin/gaiax-opa

WORKDIR /policies
USER $USER:$GROUP
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin:/
EXPOSE 8181/tcp
EXPOSE 50051/tcp
ENTRYPOINT ["/usr/local/bin/gaiax-opa"]
CMD ["run"]
