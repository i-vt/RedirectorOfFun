FROM ubuntu:22.04

LABEL maintainer="RoF"
LABEL description="Nginx C2 redirector with operator control plane"

ENV DEBIAN_FRONTEND=noninteractive

# ─── Install dependencies ─────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    nginx \
    certbot \
    python3-certbot-nginx \
    net-tools \
    curl \
    openssl \
    cron \
    && rm -rf /var/lib/apt/lists/*

# ─── Copy config and assets ───────────────────────────────────────────────────
COPY default.conf         /etc/nginx/sites-enabled/default
COPY decoy/index.html     /var/www/html/index.html
COPY decoy/maintenance.html /var/www/html/maintenance.html
COPY rof-cron             /etc/cron.d/rof
COPY blocklist-update.sh  /usr/local/bin/blocklist-update.sh

RUN chmod +x /usr/local/bin/blocklist-update.sh \
    && chmod 644 /etc/cron.d/rof \
    && touch /etc/nginx/blocklist.conf

# ─── Substitute placeholders at container start ───────────────────────────────
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
