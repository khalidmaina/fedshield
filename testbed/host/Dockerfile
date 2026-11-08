# Image for every simulated host (and the c2-server) in the FedShield testbed.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# Tools the workloads and the simulated attacks use. cron only provides /etc/cron.d
# for the persistence attack; no cron daemon runs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates coreutils cron curl findutils gcc grep gzip libc6-dev make \
        netcat-openbsd procps python3 sed sqlite3 tar \
    && rm -rf /var/lib/apt/lists/*
COPY agent.sh /fs/agent.sh
COPY roles/ /fs/roles/
RUN chmod +x /fs/agent.sh /fs/roles/*.sh
ENTRYPOINT ["/fs/agent.sh"]
