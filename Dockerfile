FROM golang:1.16-alpine as build

RUN apk update \
  && apk upgrade --no-cache \
  && apk add --no-cache bash git ca-certificates jq
RUN go mod vendor
RUN CGO_ENABLED=0 go get -a -ldflags '-s' -u github.com/cloudflare/cf-terraforming/...

ENTRYPOINT ["cf-terraforming"]
