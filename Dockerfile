FROM alpine:3.6

RUN adduser tgsocks -u 10000 -D

RUN apk add --no-cache python3

COPY tgsocksproxy.py config.py /home/tgsocks/

RUN chown -R tgsocks:tgsocks /home/tgsocks

USER tgsocks

WORKDIR /home/tgsocks/
CMD ["./tgsocksproxy.py"]
