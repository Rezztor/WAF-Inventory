#!/bin/sh
# Install WAF Inventory with Docker Compose in this folder: master key, admin account, start, print the URL.
# Run it again to reset the admin password.
set -eu
cd "$(dirname "$0")"
command -v docker >/dev/null || { echo "Docker is required." >&2; exit 1; }
[ -f compose.yaml ] || { echo "compose.yaml must be in the same folder as install.sh." >&2; exit 1; }

umask 077
mkdir -p secrets
if [ ! -f secrets/master_key ]; then
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' > secrets/master_key
  chmod 0444 secrets/master_key  # the folder stays 0700; the container user (UID 10001) must read the file
  echo "Created secrets/master_key. Back it up somewhere safe, separately from the database."
fi

printf 'Admin username [admin]: '
read -r user
user=${user:-admin}
trap 'stty echo 2>/dev/null || :' EXIT
trap 'exit 130' INT TERM
stty -echo 2>/dev/null || true
printf 'Admin password (at least 12 characters): '
read -r pw
printf '\nAgain: '
read -r pw2
stty echo 2>/dev/null || true
echo
[ "$pw" = "$pw2" ] || { echo "Passwords do not match." >&2; exit 1; }

docker compose pull --quiet
# The password goes over stdin only: never on the command line, in the environment or on disk.
printf '%s\n' "$pw" | docker compose run --rm -T --no-deps waf-inventory waf-inv reset-password "$user" --password-stdin
unset pw pw2
docker compose up -d

printf 'Waiting for the console'
i=0
until docker compose exec -T waf-inventory python -c "import ssl, urllib.request as u; u.urlopen('https://127.0.0.1:8443/healthz', context=ssl._create_unverified_context(), timeout=2)" >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 30 ] || { echo; echo "Not up after 60 s: docker compose logs waf-inventory" >&2; exit 1; }
  printf '.'; sleep 2
done
echo
echo "WAF Inventory is running at https://$(hostname -f 2>/dev/null || hostname):8443  (user: $user)"
echo "HTTPS certificate $(docker compose exec -T waf-inventory waf-inv tls show 2>/dev/null)"
echo "Check your browser shows the same fingerprint before you sign in."
