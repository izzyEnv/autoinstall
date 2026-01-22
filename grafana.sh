#!/usr/bin/env bash
#
# install_monitoring_fixed.sh
# Perbaikan: andal memeriksa port/owner, membuat unit yang hilang, install grafana bila perlu.
# Target: Ubuntu 20.04 / 22.04 (amd64)
set -euo pipefail
IFS=$'\n\t'

PROM_VERSION="2.44.0"
NODE_EXPORTER_VERSION="1.6.1"
PROM_USER="pemonitor"
PROM_HOME="/var/lib/pemonitor"
PROM_CONF_DIR="/etc/prometheus"
PROM_DATA_DIR="/var/lib/prometheus"
GRAFANA_DASHBOARDS_DIR="/var/lib/grafana/dashboards"
GRAFANA_PROV_DIR="/etc/grafana/provisioning"
GRAFANA_DATASOURCE_DIR="${GRAFANA_PROV_DIR}/datasources"
GRAFANA_DASHBOARD_PROV_DIR="${GRAFANA_PROV_DIR}/dashboards"
RETRY_MAX=6
RETRY_SLEEP=5
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi

PROM_BIN="/usr/local/bin/prometheus"
PROMTOOL_BIN="/usr/local/bin/promtool"
NODE_BIN="/usr/local/bin/node_exporter"

log() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] $*"; }
err() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [ERROR] $*" >&2; }

retry() {
  local n=0 cmd="$*"
  until $cmd; do
    n=$((n+1))
    if [ $n -ge "$RETRY_MAX" ]; then
      err "Command failed after $n attempts: $cmd"
      return 1
    fi
    log "Retry #$n after ${RETRY_SLEEP}s..."
    sleep "$RETRY_SLEEP"
  done
}

download() {
  local url="$1" dest="$2"
  log "Downloading $url -> $dest"
  retry curl -fsSL "$url" -o "$dest"
}

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "Run as root: sudo bash $0"
    exit 1
  fi
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  log "apt-get update"
  retry apt-get update -y
  log "apt-get install -y $*"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

# Check if TCP port is in use (LISTEN). Return 0 if in use.
is_port_in_use() {
  local port="$1"
  if ss -ltnp "sport = :$port" 2>/dev/null | tail -n +2 | grep -q .; then
    return 0
  fi
  return 1
}

# Get the first PID listening on port (or empty)
get_pid_on_port() {
  local port="$1"
  # parse pid=1234 from ss output
  ss -ltnp "sport = :$port" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -n1 || true
}

get_cmd_for_pid() {
  local pid="$1"
  if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
    readlink -f "/proc/$pid/exe" 2>/dev/null || true
  fi
}

# safe start: returns 0 if started or already running, non-zero otherwise
check_and_start_service() {
  local svc="$1" port="$2" expected_bin="$3"
  log "Checking ${svc} (expect ${expected_bin}) on port ${port}"

  if ! systemctl cat "${svc}" >/dev/null 2>&1; then
    log "Unit ${svc} does not exist."
    return 2
  fi

  if systemctl is-active --quiet "${svc}"; then
    log "Service ${svc} already active."
    return 0
  fi

  if is_port_in_use "${port}"; then
    local pid
    pid="$(get_pid_on_port "${port}" || true)"
    if [ -z "$pid" ]; then
      err "Port ${port} in use but PID not found. Will not start ${svc}."
      return 3
    fi
    local proc_cmd
    proc_cmd="$(get_cmd_for_pid "$pid" || true)"
    log "Port ${port} used by pid ${pid} -> ${proc_cmd:-(unknown)}"
    if [ -n "$expected_bin" ] && [ -n "$proc_cmd" ] && [ "$proc_cmd" = "$expected_bin" ]; then
      log "Expected binary is already listening on ${port}; treating as running."
      return 0
    else
      err "Collision: port ${port} used by ${proc_cmd:-pid $pid}; not starting ${svc}."
      return 3
    fi
  fi

  log "Port ${port} free -> enabling & starting ${svc}"
  if ! systemctl enable --now "${svc}"; then
    err "Failed to enable/start ${svc}"
    return 1
  fi
  sleep 2
  if systemctl is-active --quiet "${svc}"; then
    log "${svc} started"
    return 0
  else
    err "${svc} did not become active"
    return 1
  fi
}

urlencode() { python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$*"; }

### MAIN
ensure_root
log "Start installer (fixed)"

# basic tools
apt_install curl wget tar gnupg ca-certificates jq openssl procps

# create pemonitor user
if id -u "${PROM_USER}" >/dev/null 2>&1; then
  log "User ${PROM_USER} exists"
else
  useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir "${PROM_HOME}" "${PROM_USER}"
  mkdir -p "${PROM_HOME}"
  chown -R "${PROM_USER}:${PROM_USER}" "${PROM_HOME}"
  log "Created ${PROM_USER}"
fi

### Prometheus install
PROM_TGZ="/tmp/prometheus-${PROM_VERSION}.linux-${ARCH}.tar.gz"
PROM_URL="https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-${ARCH}.tar.gz"

if [ ! -x "${PROM_BIN}" ] || ! ("${PROM_BIN}" --version 2>/dev/null | grep -q "${PROM_VERSION}"); then
  log "Installing Prometheus ${PROM_VERSION}"
  rm -f "${PROM_TGZ}"
  download "${PROM_URL}" "${PROM_TGZ}"
  tar -xzf "${PROM_TGZ}" -C /tmp
  EXDIR="/tmp/prometheus-${PROM_VERSION}.linux-${ARCH}"
  install -m 0755 "${EXDIR}/prometheus" "${PROM_BIN}"
  install -m 0755 "${EXDIR}/promtool" "${PROMTOOL_BIN}"
  mkdir -p "${PROM_CONF_DIR}" "${PROM_DATA_DIR}"
  cp -r "${EXDIR}/consoles" "${PROM_CONF_DIR}/" || true
  cp -r "${EXDIR}/console_libraries" "${PROM_CONF_DIR}/" || true
  chown -R "${PROM_USER}:${PROM_USER}" "${PROM_CONF_DIR}" "${PROM_DATA_DIR}" "${PROM_HOME}"
  rm -rf "${EXDIR}" "${PROM_TGZ}"
else
  log "Prometheus binary ok"
fi

# config
cat > "${PROM_CONF_DIR}/prometheus.yml" <<'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node_exporter'
    static_configs:
      - targets: ['localhost:9100']
EOF
chown "${PROM_USER}:${PROM_USER}" "${PROM_CONF_DIR}/prometheus.yml"
chmod 640 "${PROM_CONF_DIR}/prometheus.yml"

# unit
PROM_SERVICE="/etc/systemd/system/prometheus.service"
if [ ! -f "${PROM_SERVICE}" ]; then
  cat > "${PROM_SERVICE}" <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=${PROM_USER}
Group=${PROM_USER}
Type=simple
ExecStart=${PROM_BIN} --config.file=${PROM_CONF_DIR}/prometheus.yml --storage.tsdb.path=${PROM_DATA_DIR} --web.listen-address=:9090
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  chown root:root "${PROM_SERVICE}"
  chmod 644 "${PROM_SERVICE}"
  log "Created prometheus.service"
else
  log "prometheus.service exists"
fi

# start/skip Prometheus
check_and_start_service "prometheus.service" 9090 "${PROM_BIN}" || log "prometheus check_and_start non-zero"

### Node Exporter install
NODE_TGZ="/tmp/node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}.tar.gz"
NODE_URL="https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}.tar.gz"

if [ ! -x "${NODE_BIN}" ] || ! ("${NODE_BIN}" --version 2>/dev/null | grep -q "${NODE_EXPORTER_VERSION}"); then
  log "Installing Node Exporter ${NODE_EXPORTER_VERSION}"
  rm -f "${NODE_TGZ}"
  download "${NODE_URL}" "${NODE_TGZ}"
  tar -xzf "${NODE_TGZ}" -C /tmp
  EXDIR="/tmp/node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}"
  install -m 0755 "${EXDIR}/node_exporter" "${NODE_BIN}"
  chown "${PROM_USER}:${PROM_USER}" "${NODE_BIN}"
  rm -rf "${EXDIR}" "${NODE_TGZ}"
else
  log "Node exporter binary ok"
fi

# node_exporter unit
NODE_SERVICE="/etc/systemd/system/node_exporter.service"
if [ ! -f "${NODE_SERVICE}" ]; then
  cat > "${NODE_SERVICE}" <<EOF
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=${PROM_USER}
Group=${PROM_USER}
Type=simple
ExecStart=${NODE_BIN} --web.listen-address=":9100"
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  chown root:root "${NODE_SERVICE}"
  chmod 644 "${NODE_SERVICE}"
  log "Created node_exporter.service"
else
  log "node_exporter.service exists"
fi

check_and_start_service "node_exporter.service" 9100 "${NODE_BIN}" || log "node_exporter check_and_start non-zero"

### Grafana install if needed
if ! systemctl cat grafana-server.service >/dev/null 2>&1; then
  log "Grafana unit missing -> installing grafana package"
  if [ ! -f /etc/apt/sources.list.d/grafana.list ]; then
    curl -fsSL https://packages.grafana.com/gpg.key | apt-key add -
    echo "deb https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
  fi
  retry apt-get update -y
  apt_install grafana
else
  log "Grafana unit present"
fi

GRAFANA_ADMIN_USER="admin"
GRAFANA_ADMIN_PASSWORD="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 16 || echo 'ChangeMe123!')"
log "Setting Grafana admin password (will show at end)"
echo "GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}" > /etc/default/grafana-server
chmod 640 /etc/default/grafana-server

GRAFANA_EXPECTED_BIN="$(readlink -f /usr/sbin/grafana-server 2>/dev/null || true)"
[ -z "$GRAFANA_EXPECTED_BIN" ] && GRAFANA_EXPECTED_BIN="/usr/sbin/grafana-server"
check_and_start_service "grafana-server.service" 3000 "${GRAFANA_EXPECTED_BIN}" || log "grafana check_and_start non-zero"

# Provision Grafana datasource and dashboards
log "Provisioning Grafana"
mkdir -p "${GRAFANA_DATASOURCE_DIR}" "${GRAFANA_DASHBOARD_PROV_DIR}" "${GRAFANA_DASHBOARDS_DIR}"
chown -R grafana:grafana "${GRAFANA_DASHBOARDS_DIR}" || true
chmod 750 "${GRAFANA_DASHBOARDS_DIR}" || true

cat > "${GRAFANA_DATASOURCE_DIR}/prometheus.yml" <<EOF
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: true
EOF

cat > "${GRAFANA_DASHBOARD_PROV_DIR}/node_exporter.yml" <<EOF
apiVersion: 1
providers:
  - name: 'Node Exporter Dashboards'
    orgId: 1
    folder: ''
    type: file
    options:
      path: ${GRAFANA_DASHBOARDS_DIR}
EOF

DASH_URL_PRIMARY="https://grafana.com/api/dashboards/1860/revisions/latest/download"
DASH_LOCAL="${GRAFANA_DASHBOARDS_DIR}/node-exporter.json"
if download "${DASH_URL_PRIMARY}" "${DASH_LOCAL}"; then
  log "Dashboard downloaded"
else
  log "Failed to download dashboard; creating minimal fallback"
  cat > "${DASH_LOCAL}" <<'EOF'
{
  "annotations": {"list":[]},
  "editable": true,
  "panels":[
    {"datasource":"Prometheus","id":1,"title":"up","type":"stat","targets":[{"expr":"up{job=\"node_exporter\"}","refId":"A"}]},
    {"datasource":"Prometheus","id":2,"title":"CPU Usage","type":"graph","targets":[{"expr":"1 - avg by (instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m]))","refId":"A"}]},
    {"datasource":"Prometheus","id":3,"title":"Memory Used (%)","type":"graph","targets":[{"expr":"100 * (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))","refId":"A"}]}
  ],
  "refresh":"15s","schemaVersion":27,"title":"Node Exporter (Minimal)","uid":"node-exporter-minimal","version":1
}
EOF
fi
chown grafana:grafana "${DASH_LOCAL}" || true
chmod 640 "${DASH_LOCAL}" || true

log "Restart grafana to apply provisioning"
systemctl restart grafana-server || true
sleep 3

# Verifications (best-effort)
log "Verifying endpoints"
if curl -fsS http://127.0.0.1:9090/-/ready >/dev/null 2>&1; then log "Prometheus ready"; else log "Prometheus not ready"; fi
if curl -fsS http://127.0.0.1:9100/metrics >/dev/null 2>&1; then log "Node Exporter metrics available"; else log "Node Exporter metrics NOT available"; fi
if curl -fsS http://127.0.0.1:3000/api/health >/dev/null 2>&1; then log "Grafana healthy"; else log "Grafana NOT healthy"; fi

# Try Prometheus query for up
PROM_QUERY_URL="http://127.0.0.1:9090/api/v1/query?query=$(urlencode 'up{job=\"node_exporter\"}')"
if RES="$(curl -fsS "${PROM_QUERY_URL}" 2>/dev/null || true)"; then
  if echo "$RES" | jq -e '.data.result | length > 0' >/dev/null 2>&1; then
    VAL="$(echo "$RES" | jq -r '.data.result[0].value[1]' 2>/dev/null || true)"
    log "Prometheus up{job=\"node_exporter\"} = ${VAL}"
  else
    log "Prometheus query returned no result"
  fi
else
  log "Prometheus query failed"
fi

HOST="$(hostname -I | awk '{print $1}' || echo '127.0.0.1')"
cat <<EOF

INSTALL SUMMARY
Grafana URL : http://${HOST}:3000
Grafana admin: admin / (password below)
Prometheus   : http://127.0.0.1:9090
Node Exporter: http://127.0.0.1:9100

If service failed start, inspect:
  journalctl -u prometheus -n 200 --no-pager
  journalctl -u node_exporter -n 200 --no-pager
  journalctl -u grafana-server -n 200 --no-pager

EOF

log "Grafana admin password: ${GRAFANA_ADMIN_PASSWORD}"
log "Done"
exit 0
