# Image for every simulated host in the FedShield testbed.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl ca-certificates python3 gcc make libc6-dev sqlite3 \
        netcat-openbsd procps gzip tar cron \
    && rm -rf /var/lib/apt/lists/*
COPY roles/ /roles/
RUN chmod +x /roles/*.sh
CMD ["/roles/run.sh"]
