FROM golang:1.24-alpine as builder
LABEL authors="Philipp Seifert-Kehrer"

RUN apk update && apk add --no-cache git tzdata build-base

ARG BUILDPATH=/go/src/github.com/Posedio/gaiax-opa

#https://stackoverflow.com/a/55757473/12429735
ENV USER=pos
ENV UID=60000
ENV GROUP=posedio
ENV GID=50000

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "$(pwd)" \
    --no-create-home \
    --uid "$UID" \
    "$USER"

RUN addgroup -g "$GID" "$GROUP" && addgroup "$USER" "$GROUP"

WORKDIR ${BUILDPATH}
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
COPY main.go main.go


RUN go build --tags=gaiax_ovc -v -o gaiax-opa

FROM alpine
LABEL authors="Philipp Seifert-Kehrer"

ENV USER=pos
ENV GROUP=posedio


ARG BUILDPATH=/go/src/github.com/Posedio/gaiax-opa

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder ${BUILDPATH}/gaiax-opa /usr/local/bin/gaiax-opa

RUN mkdir -p /policies

RUN chown -R $USER:$GROUP /policies
RUN chown root:root /usr/local/bin/gaiax-opa
RUN chmod 4755 /usr/local/bin/gaiax-opa

WORKDIR /policies

USER $USER:$GROUP

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin:/



EXPOSE 8181/tcp
#EXPOSE 50055/tcp
ENTRYPOINT ["/usr/local/bin/gaiax-opa"]
CMD ["run"]
