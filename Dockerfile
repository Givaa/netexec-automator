# Self-contained image for air-gapped deployment.
#
# Build (on a host with internet):
#     docker build -t netexec-automator:latest .
#
# Export for offline transfer:
#     docker save netexec-automator:latest | gzip > netexec-automator.tar.gz
#
# Import on the air-gapped host:
#     gunzip -c netexec-automator.tar.gz | docker load
#
# Run:
#     docker run --rm -it --network host -v "$PWD":/work netexec-automator \
#         -t /work/targets.txt --combo /work/loot.txt --nmap --low-power \
#         --loot-dir /work/loot --cmd-log /work/commands.log
#
# (--network host lets the container reach the internal network directly.)

FROM python:3.12-slim

ARG DEBIAN_FRONTEND=noninteractive
ARG INSTALL_NMAP=1
ARG INSTALL_BLOODHOUND=1

# nmap is needed only for --nmap pre-scan. Drop it with --build-arg INSTALL_NMAP=0
# if you want a smaller image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        $( [ "$INSTALL_NMAP" = "1" ] && echo nmap ) \
 && rm -rf /var/lib/apt/lists/*

# Pin a recent NetExec; bloodhound-python is optional.
RUN pip install --no-cache-dir netexec \
 && if [ "$INSTALL_BLOODHOUND" = "1" ]; then pip install --no-cache-dir bloodhound; fi

# The tool itself is pure stdlib — just drop it in PATH.
WORKDIR /opt/netexec-automator
COPY netexec-automator.py /opt/netexec-automator/netexec-automator.py
COPY netexec_automator    /opt/netexec-automator/netexec_automator
COPY README.md            /opt/netexec-automator/README.md
RUN chmod +x /opt/netexec-automator/netexec-automator.py \
 && ln -s /opt/netexec-automator/netexec-automator.py /usr/local/bin/netexec-automator

# Cache, loot, and command-log live in /work so they survive container exits
# via a bind-mounted host directory.
WORKDIR /work
ENV HOME=/work

ENTRYPOINT ["netexec-automator"]
CMD ["--help"]
