# NOTE: This hash is the latest version available at the time of the CTF.
FROM ubuntu:22.04@sha256:0eb0f877e1c869a300c442c41120e778db7161419244ee5cbc6fa5f134e74736 AS base
WORKDIR /app
ADD --chmod=555 echo run
RUN echo "Alpaca{*** REDACTED ***}" > /flag.txt

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=180 JAIL_CPU=100 JAIL_MEM=10M
