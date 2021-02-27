FROM golang:1.16-alpine as build

RUN apk update \
  && apk upgrade --no-cache \
  && apk add --no-cache bash git ca-certificates jq
WORKDIR /app
COPY . /app
RUN CGO_ENABLED=0 go build -o cf-terraforming  -a -ldflags '-s' cmd/cf-terraforming/main.go

ENTRYPOINT ["cf-terraforming"]
