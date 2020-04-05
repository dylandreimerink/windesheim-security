FROM golang:v1.14.1 as builder

WORKDIR /go/src/github.com/dylandreimerink/windesheim-security
COPY . .

RUN CGO_ENABLED=0 go build -o winnote .

FROM alpine:3.8

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /go/src/github.com/dylandreimerink/windesheim-security/winnote .

CMD ["./winnote"]  