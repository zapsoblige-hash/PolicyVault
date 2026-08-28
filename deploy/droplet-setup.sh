#!/usr/bin/env bash
# PolicyVault production app-droplet first-boot setup (runbook §6; log §4).
#
# Run ONCE as root on a freshly provisioned Ubuntu LTS droplet
# (VPC-private networking; cloud firewall inbound tcp/22 only):
#
#   PV_OPS_PUBKEY="ssh-ed25519 AAAA... your-ops-key" bash droplet-setup.sh
#
# Contains NO secrets. YOU must supply the PUBLIC half of YOUR OWN
# dedicated operator ed25519 keypair via PV_OPS_PUBKEY (generate with
# `ssh-keygen -t ed25519`; the private key never leaves your operator
# machine). The script refuses to run without it.
#
# IMPORTANT: keep the root session that runs this script OPEN until
#   ssh -i ~/.ssh/pv_prod_ops pv-ops@<droplet-ip>
# succeeds from the operator host (root SSH login is disabled below).
set -euo pipefail

PV_OPS_USER="${PV_OPS_USER:-pv-ops}"
PV_OPS_PUBKEY="${PV_OPS_PUBKEY:-}"
[ -n "$PV_OPS_PUBKEY" ] || { echo "FATAL: set PV_OPS_PUBKEY to YOUR operator ed25519 PUBLIC key (ssh-keygen -t ed25519)" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || { echo "FATAL: run as root" >&2; exit 1; }

echo "== 1. operator user (key-only, sudo) =="
if ! id "$PV_OPS_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "PolicyVault ops" "$PV_OPS_USER"
fi
install -d -m 700 -o "$PV_OPS_USER" -g "$PV_OPS_USER" "/home/$PV_OPS_USER/.ssh"
printf '%s\n' "$PV_OPS_PUBKEY" > "/home/$PV_OPS_USER/.ssh/authorized_keys"
chown "$PV_OPS_USER:$PV_OPS_USER" "/home/$PV_OPS_USER/.ssh/authorized_keys"
chmod 600 "/home/$PV_OPS_USER/.ssh/authorized_keys"
# The user has no password, so sudo must be NOPASSWD (key-only model).
printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$PV_OPS_USER" > /etc/sudoers.d/90-pv-ops
chmod 440 /etc/sudoers.d/90-pv-ops

echo "== 2. sshd hardening + Option A forward binding =="
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/60-policyvault.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
# Option A kaspad transport (runbook §8; log §4): the operator host holds
# an outbound `ssh -N -R 172.17.0.1:18110:127.0.0.1:18110` to this
# droplet; binding the Docker host-gateway address needs clientspecified.
# The address is host-local — never publicly reachable (verified §11.13).
GatewayPorts clientspecified
EOF
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd

echo "== 3. unattended security updates =="
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq unattended-upgrades ca-certificates curl
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

echo "== 4. Docker Engine (tested major 29.x, held against auto-major) =="
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$(. /etc/os-release && echo "$VERSION_CODENAME")" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  DVER="$(apt-cache madison docker-ce | awk '$3 ~ /:29\./ {print $3}' | head -1)"
  CVER="$(apt-cache madison docker-ce-cli | awk '$3 ~ /:29\./ {print $3}' | head -1)"
  if [ -z "$DVER" ] || [ -z "$CVER" ]; then
    echo "FATAL: no Docker 29.x candidate in the repo — the tested major (runbook §6)." >&2
    echo "Choose an engine version DELIBERATELY; never auto-adopt a new major." >&2
    exit 1
  fi
  apt-get install -yq docker-ce="$DVER" docker-ce-cli="$CVER" containerd.io docker-compose-plugin
  apt-mark hold docker-ce docker-ce-cli
fi
docker --version | grep -Eq ' 29\.' || { echo "FATAL: docker major is not 29.x" >&2; exit 1; }

echo "== 5. deployment directories (runbook §6/§4.2) =="
install -d -m 755 -o root -g root /opt/policyvault
install -d -m 700 -o root -g root /etc/cloudflared

echo "== 6. verification summary =="
id "$PV_OPS_USER"
docker --version
docker compose version
sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|gatewayports)'
echo
echo "OK: droplet base setup complete."
echo "NEXT (log §5 / runbook §11):"
echo "  1. From the operator host, VERIFY ssh -i ~/.ssh/pv_prod_ops ${PV_OPS_USER}@<droplet-ip> BEFORE closing this session."
echo "  2. Ship your release image (docker save | gzip + .sha256 with a BASENAME checksum), sha256sum -c, docker load,"
echo "     then verify the loaded image ID equals YOUR recorded content-addressed image ID (docker images --no-trunc)."
echo "  3. Stage /opt/policyvault: docker-compose.prod.yml (read-only) + prod.env (root:root 600, from deploy/prod.env.example)."
