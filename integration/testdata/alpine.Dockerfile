FROM alpine:3.22

RUN apk add --no-cache ca-certificates coreutils openrc

STOPSIGNAL SIGTERM
CMD ["/sbin/init"]
