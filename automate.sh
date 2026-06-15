#!/bin/bash
# Modified Version of https://github.com/coffeegist/now-you-see-me
# Enhanced with: root check, input validation, dry-run, verbose, teardown,
# profiles, blocklist, UA filtering, log scrub, webhook notifications, status+

NORMAL=`echo "\033[m"`
BRED=`printf "\e[1;31m"`
BGREEN=`printf "\e[1;32m"`
BYELLOW=`printf "\e[1;33m"`
COLUMNS=12

# ─── Globals ────────────────────────────────────────────────────────────────
DRY_RUN=0
VERBOSE=0
WEBHOOK_URL=""
CONF_DST="/etc/nginx/sites-enabled/default"
PROFILES_DIR="./profiles"
BLOCKLIST_FILE="/etc/nginx/blocklist.conf"
WEBROOT="/var/www/html"

# ─── Output helpers ─────────────────────────────────────────────────────────
nysm_action()  { printf "\n${BGREEN}[+]${NORMAL} $1\n"; }
nysm_warning() { printf "\n${BYELLOW}[!]${NORMAL} $1\n"; }
nysm_error()   { printf "\n${BRED}[!] $1${NORMAL}\n"; }

error_exit() {
  echo -e "\n$1\n" 1>&2
  exit 1
}

check_errors() {
  if [ $? -ne 0 ]; then
    nysm_error "An error occurred..."
    error_exit "Exiting..."
  fi
}

nysm_confirm() {
  read -r -p "$1 [y/N] " response
  case "$response" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *)                  return 1 ;;
  esac
}

# ─── Command runner (respects dry-run and verbose flags) ────────────────────
run_cmd() {
  if [ $VERBOSE -eq 1 ]; then
    echo "  >> $*"
  fi
  if [ $DRY_RUN -eq 0 ]; then
    "$@"
  fi
}

# ─── Pre-flight checks ──────────────────────────────────────────────────────
check_root() {
  if [[ $EUID -ne 0 ]]; then
    nysm_error "This script must be run as root."
    exit 1
  fi

  # Fix "sudo: unable to resolve host <hostname>" warning.
  # Occurs when the system hostname is not in /etc/hosts — common on VPS images.
  # sudo looks up the hostname on every invocation and warns noisily if it
  # cannot resolve it. Harmless but confusing. Add 127.0.1.1 <hostname> if absent.
  local hn
  hn=$(hostname 2>/dev/null || true)
  if [ -n "$hn" ] && ! grep -qP "^\S+\s+${hn}(\s|$)" /etc/hosts 2>/dev/null; then
    echo "127.0.1.1 $hn" >> /etc/hosts
    nysm_action "Added '$hn' to /etc/hosts (fixes sudo hostname warning)."
  fi
}

validate_domain() {
  local domain=$1
  if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
    nysm_error "Invalid domain name: '$domain'"
    return 1
  fi
  return 0
}

validate_c2() {
  local c2=$1
  if [[ ! "$c2" =~ ^[a-zA-Z0-9._-]+:[0-9]{1,5}$ ]]; then
    nysm_error "Invalid C2 address: '$c2' (expected format: IP:Port or host:Port)"
    return 1
  fi
  local port="${c2##*:}"
  if (( port < 1 || port > 65535 )); then
    nysm_error "Invalid port: $port"
    return 1
  fi
  return 0
}

# ─── Port conflict resolution ────────────────────────────────────────────────
# Finds and stops anything occupying port 80 or 443 before nginx starts.
# Uses a polling loop with SIGKILL escalation rather than a single sleep,
# because systemctl stop is async and returns before the port is actually free.
nysm_clear_ports() {
  nysm_action "Checking for port conflicts on 80 and 443..."

  port_is_free() {
    ! ss -tlnp "sport = :$1" 2>/dev/null | grep -q ":$1"
  }

  for port in 80 443; do
    if port_is_free "$port"; then
      nysm_action "Port $port is free."
      continue
    fi

    local pids
    pids=$(ss -tlnp "sport = :$port" 2>/dev/null \
           | grep -oP 'pid=\K[0-9]+' | sort -u)

    for pid in $pids; do
      local proc_name
      proc_name=$(ps -p "$pid" -o comm= 2>/dev/null | tr -d ' ')
      nysm_warning "Port $port occupied by '$proc_name' (PID $pid) — stopping..."

      case "$proc_name" in
        apache2|apache|httpd)
          systemctl stop apache2 2>/dev/null || systemctl stop httpd 2>/dev/null || true
          systemctl disable apache2 2>/dev/null || true
          ;;
        nginx)
          # Stop via systemd AND send SIGTERM directly — systemctl stop on a
          # failed/partially-started nginx may return immediately without
          # actually killing the process.
          systemctl stop nginx 2>/dev/null || true
          pkill -TERM -x nginx 2>/dev/null || true
          ;;
        python3|python|python3.*)
          kill -TERM "$pid" 2>/dev/null || true
          ;;
        *)
          kill -TERM "$pid" 2>/dev/null || true
          ;;
      esac
    done

    # Poll up to 10 seconds for the port to be free.
    # Escalate to SIGKILL at the 5-second mark.
    local elapsed=0
    while [ $elapsed -lt 10 ]; do
      sleep 1
      elapsed=$(( elapsed + 1 ))

      if port_is_free "$port"; then
        nysm_action "Port $port cleared (after ${elapsed}s)."
        break
      fi

      if [ $elapsed -eq 5 ]; then
        nysm_warning "Port $port still busy after 5s — escalating to SIGKILL..."
        local stuck_pids
        stuck_pids=$(ss -tlnp "sport = :$port" 2>/dev/null \
                     | grep -oP 'pid=\K[0-9]+' | sort -u)
        for spid in $stuck_pids; do
          nysm_warning "SIGKILL → PID $spid"
          kill -KILL "$spid" 2>/dev/null || true
        done
        # systemd may restart nginx automatically — stop that too
        systemctl stop nginx 2>/dev/null || true
      fi
    done

    # Final check — give up if still occupied
    if ! port_is_free "$port"; then
      nysm_error "Port $port still in use after 10s."
      ss -tlnp "sport = :$port"
      error_exit "Could not free port $port. Check for processes outside systemd and re-run."
    fi
  done
}

# ─── DNS verification ────────────────────────────────────────────────────────
# Let's Encrypt will try to reach this server via the domain. If DNS points
# elsewhere (e.g. at the C2 server) the ACME challenge fails.
verify_dns() {
  local domain=$1

  nysm_action "Verifying DNS for $domain..."

  # Resolve the domain using Python (no extra packages needed)
  local dns_ip
  dns_ip=$(python3 -c "import socket; print(socket.gethostbyname('$domain'))" 2>/dev/null)

  if [ -z "$dns_ip" ]; then
    nysm_error "DNS lookup for '$domain' returned nothing."
    nysm_error "Make sure an A record exists: $domain → <this server's IP>"
    error_exit "Fix DNS and re-run."
  fi

  # Detect this server's public IP
  local my_ip
  my_ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
       || curl -s --max-time 5 https://ifconfig.me 2>/dev/null \
       || hostname -I | awk '{print $1}')

  if [ "$dns_ip" != "$my_ip" ]; then
    nysm_error "DNS mismatch detected!"
    nysm_error "  $domain resolves to : $dns_ip"
    nysm_error "  This server's IP is  : $my_ip"
    nysm_error "Let's Encrypt will try to reach $dns_ip on port 80 — the ACME challenge WILL fail."
    nysm_error "Update your DNS A record so $domain points to $my_ip and wait for propagation."
    if ! nysm_confirm "I have fixed DNS and want to continue anyway:"; then
      error_exit "Aborted. Fix DNS and re-run."
    fi
  else
    nysm_action "DNS OK: $domain → $dns_ip (matches this server)"
  fi
}

# ─── Webhook notification ────────────────────────────────────────────────────
send_webhook() {
  if [ -n "$WEBHOOK_URL" ]; then
    local message=$1
    curl -s -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"[NYSM] $message\"}" \
      "$WEBHOOK_URL" > /dev/null 2>&1
    nysm_action "Webhook notification sent."
  fi
}

# ─── Install ─────────────────────────────────────────────────────────────────
nysm_install() {
  # BUG FIX 1: Clear port conflicts BEFORE apt tries to start nginx
  if [ $DRY_RUN -eq 0 ]; then
    nysm_clear_ports
  fi

  nysm_action "Updating package lists..."
  run_cmd apt-get update
  check_errors

  nysm_action "Installing nginx, certbot & tools..."
  run_cmd apt-get install -y certbot python3-certbot-nginx nginx net-tools curl openssl
  check_errors

  # BUG FIX 4: Certbot's apt package installs its own systemd timer (certbot.timer)
  # which conflicts with our nysm-cron renewal job. Disable it — we manage renewals.
  if systemctl is-enabled certbot.timer &>/dev/null; then
    nysm_action "Disabling certbot systemd timer (using nysm-cron instead)..."
    run_cmd systemctl stop certbot.timer
    run_cmd systemctl disable certbot.timer
  fi

  nysm_action "Deploying certbot renewal cronjob..."
  run_cmd cp nysm-cron /etc/cron.d/nysm
  check_errors

  nysm_action "Initialising blocklist file..."
  if [ $DRY_RUN -eq 0 ]; then
    touch "$BLOCKLIST_FILE"
    bash blocklist-update.sh
  fi

  # BUG FIX 2: /var/www/html may not exist if nginx never started successfully.
  # Always create it explicitly before copying decoy pages into it.
  nysm_action "Creating webroot and deploying decoy pages..."
  run_cmd mkdir -p "$WEBROOT"
  run_cmd cp decoy/index.html       "$WEBROOT/index.html"
  run_cmd cp decoy/maintenance.html "$WEBROOT/maintenance.html"

  # Ensure nginx is actually running after install (port clearing may have
  # stopped a previous instance; apt does not always restart it)
  if [ $DRY_RUN -eq 0 ]; then
    if ! systemctl is-active --quiet nginx; then
      nysm_action "Starting nginx..."
      systemctl start nginx
      check_errors
    fi
  fi

  nysm_action "Finished installing dependencies!"
}

# ─── Initialize ──────────────────────────────────────────────────────────────
nysm_initialize() {
  nysm_action "Configuring nginx redirector..."

  # Accept args or prompt interactively
  if [ "$#" -ge 2 ]; then
    domain_name=$1
    c2_server=$2
    ua_pattern=${3:-""}
    use_https_upstream=${4:-"0"}
  else
    read -r -p "Domain name? (ex: updates.example.com) " domain_name
    read -r -p "C2 server address? (IP:Port)             " c2_server
    read -r -p "User-agent filter pattern (blank = allow all): " ua_pattern
    read -r -p "Proxy to C2 over HTTPS? [y/N] " https_answer
    [[ "$https_answer" =~ ^[yY] ]] && use_https_upstream="1" || use_https_upstream="0"
  fi

  # Validate inputs
  validate_domain "$domain_name" || error_exit "Aborting: invalid domain."
  validate_c2     "$c2_server"   || error_exit "Aborting: invalid C2 address."

  # BUG FIX 5: Verify DNS points HERE before running certbot.
  # The previous failure was because gooner.cam resolved to the MSF server IP,
  # not the redirector — Let's Encrypt couldn't reach the ACME challenge endpoint.
  if [ $DRY_RUN -eq 0 ]; then
    verify_dns "$domain_name"
  fi

  # Escape values for safe sed substitution
  local safe_domain safe_c2
  safe_domain=$(printf '%s' "$domain_name" | sed 's/[\/&]/\\&/g')
  safe_c2=$(printf '%s'     "$c2_server"   | sed 's/[\/&]/\\&/g')

  local scheme="http"
  [ "$use_https_upstream" = "1" ] && scheme="https"

  # ── Step 1: Deploy the HTTP-only config (serves the ACME webroot challenge)
  nysm_action "Deploying initial HTTP config for ACME challenge..."
  run_cmd cp ./default.conf "$CONF_DST"
  run_cmd sed -i "s/<DOMAIN_NAME>/$safe_domain/g" "$CONF_DST"
  run_cmd sed -i "s/<C2_SERVER>/$safe_c2/g"       "$CONF_DST"
  run_cmd sed -i "s/<C2_SCHEME>/$scheme/g"         "$CONF_DST"

  if [ -n "$ua_pattern" ]; then
    local safe_ua
    safe_ua=$(printf '%s' "$ua_pattern" | sed 's/[\/&]/\\&/g')
    run_cmd sed -i "s|#UA_FILTER# ||g"         "$CONF_DST"
    run_cmd sed -i "s|<UA_PATTERN>|$safe_ua|g" "$CONF_DST"
  else
    run_cmd sed -i "/#UA_FILTER#/d" "$CONF_DST"
  fi

  # Reload nginx with the substituted HTTP config so it can serve
  # /.well-known/acme-challenge/ from /var/www/html during the ACME challenge
  nysm_action "Reloading nginx with HTTP config..."
  run_cmd nginx -t
  check_errors
  run_cmd systemctl reload nginx
  check_errors

  # ── Step 2: Obtain certificate using webroot authenticator
  # BUG FIX 3: Use --webroot instead of --nginx.
  # --nginx modifies the live config inline, which creates a DUPLICATE SSL
  # server block when we later uncomment the #nysm# block, causing:
  #   "conflicting server name ... ignored" → nginx restart fails.
  # --webroot drops the challenge token under /var/www/html and leaves the
  # nginx config completely untouched. Our #nysm# mechanism then works cleanly.
  nysm_action "Obtaining SSL certificate via Let's Encrypt (webroot)..."
  if [ $DRY_RUN -eq 0 ]; then
    certbot certonly \
      --webroot \
      --webroot-path "$WEBROOT" \
      --register-unsafely-without-email \
      --agree-tos \
      -d "$domain_name"
    check_errors
  fi

  # ── Step 3: Activate the full HTTPS config
  # Remove the HTTP proxy server block (between the NYSM_HTTP markers),
  # then uncomment the HTTP→HTTPS redirect block and the HTTPS proxy block.
  nysm_action "Activating HTTPS config (removing HTTP proxy block, enabling SSL block)..."
  if [ $DRY_RUN -eq 0 ]; then
    # Remove the pre-cert HTTP proxy server block (marked in the template)
    sed -i '/# ─── NYSM_HTTP_START/,/# ─── NYSM_HTTP_END/d' "$CONF_DST"
    # Uncomment the HTTPS proxy block
    sed -i "s/^#nysm#//g" "$CONF_DST"
    # Uncomment the HTTP → HTTPS redirect block
    sed -i "s/^#redirect#//g" "$CONF_DST"
  fi

  # Final config test and reload
  nysm_action "Testing final nginx configuration..."
  run_cmd nginx -t
  check_errors

  nysm_action "Restarting nginx with SSL..."
  run_cmd systemctl restart nginx
  check_errors

  # Update /etc/hosts
  if [ $DRY_RUN -eq 0 ]; then
    grep -qxF "127.0.0.1 $domain_name" /etc/hosts || \
      echo "127.0.0.1 $domain_name" >> /etc/hosts
  fi

  nysm_save_profile "$domain_name" "$c2_server" "$ua_pattern" "$use_https_upstream"
  send_webhook "Redirector online: $domain_name → $c2_server"
  nysm_action "Done! Redirector is live at https://$domain_name"
}

nysm_setup() {
  nysm_install
  nysm_initialize "$@"
}

# ─── Teardown ────────────────────────────────────────────────────────────────
nysm_teardown() {
  nysm_action "Teardown NYSM redirector"

  if ! nysm_confirm "This removes nginx, certificates, cron, and all configs. Continue?"; then
    nysm_warning "Teardown aborted."
    return
  fi

  local domain_name
  read -r -p "Domain name to revoke certificate for: " domain_name
  validate_domain "$domain_name" || error_exit "Invalid domain."

  nysm_action "Revoking and removing SSL certificate..."
  run_cmd certbot delete --cert-name "$domain_name"

  nysm_action "Removing nginx config and blocklist..."
  run_cmd rm -f "$CONF_DST"
  run_cmd rm -f "$BLOCKLIST_FILE"

  nysm_action "Removing cron job..."
  run_cmd rm -f /etc/cron.d/nysm

  nysm_action "Stopping nginx..."
  run_cmd systemctl stop nginx.service

  if nysm_confirm "Purge nginx and certbot packages?"; then
    run_cmd apt-get purge -y nginx certbot python3-certbot-nginx
    run_cmd apt-get autoremove -y
  fi

  nysm_action "Cleaning /etc/hosts entry..."
  run_cmd sed -i "/127.0.0.1 $domain_name/d" /etc/hosts

  nysm_action "Scrubbing nginx logs..."
  run_cmd truncate -s 0 /var/log/nginx/access.log 2>/dev/null || true
  run_cmd truncate -s 0 /var/log/nginx/error.log  2>/dev/null || true

  send_webhook "Redirector for $domain_name has been torn down and scrubbed."
  nysm_action "Teardown complete."
}

# ─── Profile management ──────────────────────────────────────────────────────
nysm_save_profile() {
  local domain=$1 c2=$2 ua=${3:-""} https=${4:-"0"}
  mkdir -p "$PROFILES_DIR"
  local profile_file="$PROFILES_DIR/${domain}.conf"
  cat > "$profile_file" <<EOF
domain_name=$domain
c2_server=$c2
ua_pattern=$ua
use_https_upstream=$https
EOF
  nysm_action "Profile saved → $profile_file"
}

nysm_load_profile() {
  local profiles=("$PROFILES_DIR"/*.conf)
  if [ ! -f "${profiles[0]}" ]; then
    nysm_warning "No profiles found in $PROFILES_DIR"
    return
  fi

  printf "\nAvailable profiles:\n"
  local i=1
  for p in "${profiles[@]}"; do
    echo "  $i) $(basename "$p" .conf)"
    ((i++))
  done

  read -r -p "Select profile number: " sel
  local chosen="${profiles[$((sel-1))]}"
  if [ ! -f "$chosen" ]; then
    nysm_error "Invalid selection."
    return
  fi

  source "$chosen"
  nysm_action "Loaded profile: $(basename "$chosen")"
  nysm_initialize "$domain_name" "$c2_server" "$ua_pattern" "$use_https_upstream"
}

# ─── Blocklist update ────────────────────────────────────────────────────────
nysm_update_blocklist() {
  nysm_action "Updating IP blocklist..."
  run_cmd bash blocklist-update.sh
  if [ $DRY_RUN -eq 0 ]; then
    nginx -t && systemctl reload nginx
  fi
  nysm_action "Blocklist updated and nginx reloaded."
}

# ─── Log scrub ───────────────────────────────────────────────────────────────
nysm_scrub_logs() {
  nysm_action "Scrubbing nginx logs..."
  run_cmd truncate -s 0 /var/log/nginx/access.log
  run_cmd truncate -s 0 /var/log/nginx/error.log
  nysm_action "Logs cleared."
}

# ─── Status ──────────────────────────────────────────────────────────────────
nysm_status() {
  printf "\n${BGREEN}============= NYSM Status =============${NORMAL}\n"

  printf "\n${BYELLOW}--- nginx Processes ---${NORMAL}\n"
  ps aux | grep -E 'nginx' | grep -v grep

  printf "\n${BYELLOW}--- Listening Ports ---${NORMAL}\n"
  netstat -tulpn | grep -E 'nginx'

  printf "\n${BYELLOW}--- Established Connections ---${NORMAL}\n"
  netstat -an | grep ESTABLISHED | grep -v '127.0.0.1' | head -20

  printf "\n${BYELLOW}--- Certificate Expiry ---${NORMAL}\n"
  for cert in /etc/letsencrypt/live/*/cert.pem; do
    [ -f "$cert" ] || continue
    local domain
    domain=$(echo "$cert" | awk -F'/' '{print $5}')
    local expiry
    expiry=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
    local days_left
    days_left=$(( ( $(date -d "$expiry" +%s) - $(date +%s) ) / 86400 ))
    if (( days_left < 14 )); then
      printf "  ${BRED}$domain: expires $expiry ($days_left days) ← RENEW SOON${NORMAL}\n"
    else
      printf "  $domain: expires $expiry ($days_left days)\n"
    fi
  done

  printf "\n${BYELLOW}--- Blocklist Entries ---${NORMAL}\n"
  if [ -f "$BLOCKLIST_FILE" ]; then
    local count
    count=$(grep -c "^deny" "$BLOCKLIST_FILE" 2>/dev/null || echo 0)
    echo "  $count IPs/CIDRs blocked"
  else
    echo "  No blocklist found."
  fi

  printf "\n${BYELLOW}--- Log Sizes ---${NORMAL}\n"
  du -sh /var/log/nginx/access.log /var/log/nginx/error.log 2>/dev/null

  printf "\n${BYELLOW}--- Last Renewal Attempt ---${NORMAL}\n"
  grep "Cert is due\|Renewal succeeded\|no renewal" \
    /var/log/letsencrypt/letsencrypt.log 2>/dev/null | tail -3 || echo "  No renewal log found."

  printf "\n${BGREEN}=======================================${NORMAL}\n"
}

# ─── Usage ───────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF

Usage: $(basename "$0") [OPTIONS] [domain c2_server]

Options:
  -d            Dry-run mode  (preview changes, nothing applied)
  -v            Verbose mode  (print each command before running)
  -w <url>      Webhook URL for Slack/Teams/Discord notifications
  -h            Show this help

Positional arguments (skip interactive prompts):
  domain        FQDN for the redirector  (e.g. updates.example.com)
  c2_server     C2 address in IP:Port     (e.g. 10.0.0.1:443)

Examples:
  sudo $(basename "$0")                                 # interactive menu
  sudo $(basename "$0") updates.example.com 10.0.0.1:443
  sudo $(basename "$0") -d -v updates.example.com 10.0.0.1:443
  sudo $(basename "$0") -w https://hooks.slack.com/T.../... example.com 10.0.0.1:8080

EOF
}

# ─── Entry point ─────────────────────────────────────────────────────────────
while getopts "dvw:h" opt; do
  case $opt in
    d) DRY_RUN=1; nysm_warning "Dry-run mode — no changes will be applied." ;;
    v) VERBOSE=1 ;;
    w) WEBHOOK_URL="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

check_root

if [ "$#" -ge 2 ]; then
  nysm_setup "$1" "$2"
  exit 0
fi

PS3="
  NYSM - Select an Option:  "

finished=0
while (( !finished )); do
  printf "\n"
  options=(
    "Setup Nginx Redirector"
    "Load Profile"
    "Update Blocklist"
    "Check Status"
    "Scrub Logs"
    "Teardown Redirector"
    "Quit"
  )
  select opt in "${options[@]}"; do
    case $opt in
      "Setup Nginx Redirector") nysm_setup;            break ;;
      "Load Profile")           nysm_load_profile;     break ;;
      "Update Blocklist")       nysm_update_blocklist; break ;;
      "Check Status")           nysm_status;           break ;;
      "Scrub Logs")             nysm_scrub_logs;       break ;;
      "Teardown Redirector")    nysm_teardown;         break ;;
      "Quit")                   finished=1;            break ;;
      *)                        nysm_warning "Invalid option" ;;
    esac
  done
done
