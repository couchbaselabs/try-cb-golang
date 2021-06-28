FROM golang:1.16.5-buster

LABEL maintainer="Couchbase"

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential python\
    jq curl

COPY . /app

RUN go get -d -v .
RUN go build .

EXPOSE 8080

ENTRYPOINT ["./wait-for-couchbase.sh", "./try-cb-golang"]
