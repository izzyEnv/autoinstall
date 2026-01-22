#!/usr/bin/env bash
#
# install_monitoring.sh
#
# Tujuan:
#   Satu-file Bash script untuk meng-install dan mengonfigurasi Prometheus, Node Exporter, dan Grafana
#   pada Ubuntu 20.04 / 22.04 (x86_64).
#   Script non-interaktif, idempotent, memakai user sistem `pemonitor` untuk Prometheus & Node Exporter.
#
# Asumsi singkat:
#   - Mesin x86_64 (amd64), Ubuntu 20.04 atau 22.04.
#   - Versi yang dipakai (asumsi): Prometheus 2.44.0, Node Exporter 1.6.1 (jika ingin diubah, edit variabel di bawah).
#   - Script mencoba mengunduh dashboard "Node Exporter Full" dari grafana.com (ID 1860). Jika gagal, script membuat
#     dashboard minimal otomatis.
#
# Cara pakai:
#   sudo bash ./install_monitoring.sh
#
# Catatan keamanan:
#   - Script menghasilkan password Grafana admin secara acak dan menampilkannya di akhir (disimpan di memori proses
#     sementara; tidak ditulis ke file world-readable).
#   - Jangan jalankan di OS selain Ubuntu 20.04/22.04 tanpa meninjau script ini terlebih dahulu.
#
set -euo pipefail
IFS=$'\n\t'

### ====== Konfigurasi (ubah jika perlu) ======
PROM_VERSION="2.44.0"            # Ubah bila perlu
NODE_EXPORTER_VERSION="1.6.1"    # Ubah bila perlu
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
if [ "$ARCH" = "amd64" ] || [ "$ARCH" = "x86_64" ]; then
  ARCH="amd64"
fi

### ====== Helper functions ======
log() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] $*"; }
err() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [ERROR] $*" >&2; }
retry() {
  local n=0; local cmd; cmd="$*"
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
  local url="$1"; local dest="$2"
  log "Downloading $url -> $dest"
  retry curl -fsSL "$url" -o "$dest"
}

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "Script harus dijalankan sebagai root. Gunakan: sudo bash $0"
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

systemctl_enable_start() {
  local svc="$1"
  systemctl daemon-reload || true
  systemctl enable --now "$svc"
}

wait_for_http() {
  # usage: wait_for_http url timeout_seconds
  local url="$1"; local to="${2:-60}"; local t=0
  until curl -fsS "$url" >/dev/null 2>&1; do
    t=$((t+2))
    if [ "$t" -ge "$to" ]; then
      err "Timed out waiting for $url"
      return 1
    fi
    sleep 2
  done
  return 0
}

### ====== Mulai ======
ensure_root
log "Starting installation and configuration of Prometheus + Node Exporter + Grafana"

log "Creating system user '${PROM_USER}' (system account, no-login)"
if id -u "${PROM_USER}" >/dev/null 2>&1; then
  log "User ${PROM_USER} already exists, skipping creation"
else
  # Create system user no-login with home
  useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir "${PROM_HOME}" "${PROM_USER}" || {
    err "Gagal membuat user ${PROM_USER}"
    exit 1
  }
  mkdir -p "${PROM_HOME}"
  chown -R "${PROM_USER}:${PROM_USER}" "${PROM_HOME}"
  log "User ${PROM_USER} dibuat dengan home ${PROM_HOME}"
fi

log "Installing required packages (curl, wget, tar, gnupg, ca-certificates, jq)"
apt_install curl wget tar gnupg ca-certificates jq

### ====== Install Prometheus ======
PROM_TGZ="/tmp/prometheus-${PROM_VERSION}.linux-${ARCH}.tar.gz"
PROM_URL="https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-${ARCH}.tar.gz"
PROM_BIN="/usr/local/bin/prometheus"
PROMTOOL_BIN="/usr/local/bin/promtool"

if [ -x "${PROM_BIN}" ]; then
  INSTALLED_VER="$(${PROM_BIN} --version 2>/dev/null | head -n1 || true)"
  log "Prometheus binary exists (${PROM_BIN}). ${INSTALLED_VER}"
fi

if [ ! -x "${PROM_BIN}" ] || ! "${PROM_BIN}" --version 2>/dev/null | grep -q "${PROM_VERSION}"; then
  log "Installing Prometheus v${PROM_VERSION}"
  rm -f "${PROM_TGZ}"
  download "${PROM_URL}" "${PROM_TGZ}"
  # extract
  tar -xzf "${PROM_TGZ}" -C /tmp
  EXTRACT_DIR="/tmp/prometheus-${PROM_VERSION}.linux-${ARCH}"
  if [ ! -d "${EXTRACT_DIR}" ]; then
    err "Eksktraksi gagal; menunggu file: ${EXTRACT_DIR}"
    exit 1
  fi
  install -m 0755 "${EXTRACT_DIR}/prometheus" "${PROM_BIN}"
  install -m 0755 "${EXTRACT_DIR}/promtool" "${PROMTOOL_BIN}"
  mkdir -p "${PROM_CONF_DIR}" "${PROM_DATA_DIR}"
  cp -r "${EXTRACT_DIR}/consoles" "${PROM_CONF_DIR}/" || true
  cp -r "${EXTRACT_DIR}/console_libraries" "${PROM_CONF_DIR}/" || true
  chown -R "${PROM_USER}:${PROM_USER}" "${PROM_CONF_DIR}" "${PROM_DATA_DIR}" "${PROM_HOME}"
  rm -rf "${EXTRACT_DIR}" "${PROM_TGZ}"
else
  log "Prometheus v${PROM_VERSION} sudah terinstall, melewatkan instalasi."
fi

# Create prometheus.yml (idempotent)
PROM_YML="${PROM_CONF_DIR}/prometheus.yml"
log "Membuat/menimpa konfigurasi Prometheus di ${PROM_YML}"
cat > "${PROM_YML}" <<'EOF'
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

chown "${PROM_USER}:${PROM_USER}" "${PROM_YML}"
chmod 640 "${PROM_YML}"

# Create systemd service for Prometheus
PROM_SERVICE="/etc/systemd/system/prometheus.service"
log "Membuat systemd service untuk Prometheus di ${PROM_SERVICE}"
cat > "${PROM_SERVICE}" <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=${PROM_USER}
Group=${PROM_USER}
Type=simple
ExecStart=${PROM_BIN} \
  --config.file=${PROM_YML} \
  --storage.tsdb.path=${PROM_DATA_DIR} \
  --web.listen-address=:9090

Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

chown root:root "${PROM_SERVICE}"
chmod 644 "${PROM_SERVICE}"

log "Enabling & starting prometheus service"
systemctl daemon-reload
systemctl enable --now prometheus.service
sleep 2
if systemctl is-active --quiet prometheus.service; then
  log "Prometheus service aktif"
else
  err "Prometheus gagal start; lihat: journalctl -u prometheus -n 200 --no-pager"
  journalctl -u prometheus -n 200 --no-pager || true
  exit 1
fi

### ====== Install Node Exporter ======
NODE_BIN="/usr/local/bin/node_exporter"
NODE_TGZ="/tmp/node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}.tar.gz"
NODE_URL="https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}.tar.gz"

if [ ! -x "${NODE_BIN}" ] || ! "${NODE_BIN}" --version 2>/dev/null | grep -q "${NODE_EXPORTER_VERSION}"; then
  log "Installing Node Exporter v${NODE_EXPORTER_VERSION}"
  rm -f "${NODE_TGZ}"
  download "${NODE_URL}" "${NODE_TGZ}"
  tar -xzf "${NODE_TGZ}" -C /tmp
  EXTRACT_DIR="/tmp/node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}"
  install -m 0755 "${EXTRACT_DIR}/node_exporter" "${NODE_BIN}"
  chown "${PROM_USER}:${PROM_USER}" "${NODE_BIN}"
  rm -rf "${EXTRACT_DIR}" "${NODE_TGZ}"
else
  log "Node Exporter sudah terinstall, melewatkan instalasi."
fi

# systemd for node_exporter
NODE_SERVICE="/etc/systemd/system/node_exporter.service"
log "Membuat systemd service untuk node_exporter di ${NODE_SERVICE}"
cat > "${NODE_SERVICE}" <<EOF
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=${PROM_USER}
Group=${PROM_USER}
Type=simple
ExecStart=${NODE_BIN} \
  --web.listen-address=":9100"

Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

chown root:root "${NODE_SERVICE}"
chmod 644 "${NODE_SERVICE}"

log "Enabling & starting node_exporter service"
systemctl daemon-reload
systemctl enable --now node_exporter.service
sleep 2
if systemctl is-active --quiet node_exporter.service; then
  log "node_exporter service aktif"
else
  err "node_exporter gagal start; lihat: journalctl -u node_exporter -n 200 --no-pager"
  journalctl -u node_exporter -n 200 --no-pager || true
  exit 1
fi

# Verify node exporter metrics endpoint
log "Verifikasi endpoint Node Exporter http://127.0.0.1:9100/metrics"
if ! wait_for_http "http://127.0.0.1:9100/metrics" 30; then
  err "Endpoint node_exporter tidak merespon 127.0.0.1:9100"
  journalctl -u node_exporter -n 200 --no-pager || true
  exit 1
fi
log "Node Exporter merespon."

### ====== Install Grafana ======
log "Menambahkan repositori Grafana dan meng-install grafana (non-interactive)"
if [ ! -f /etc/apt/sources.list.d/grafana.list ]; then
  curl -fsSL https://packages.grafana.com/gpg.key | apt-key add -
  echo "deb https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
fi
retry apt-get update -y
apt_install grafana

# Generate a secure admin password for Grafana
GRAFANA_ADMIN_USE
