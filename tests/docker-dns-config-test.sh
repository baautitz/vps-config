#!/usr/bin/env bash
# Teste isolado da configuracao de DNS do daemon Docker. Nenhum arquivo do
# sistema ou servico real e alterado.
set -Eeuo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/secure-dns-test.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/docker"
printf '%s\n' \
    '{' \
    '  "log-driver": "json-file",' \
    '  "log-opts": {"max-size": "10m"}' \
    '}' >"$TEST_ROOT/docker/daemon.json"

# Executa só a funcao em teste. Todos os caminhos mutaveis apontam para tmp.
sed \
    -e "s|/etc/docker/daemon.json|${TEST_ROOT}/docker/daemon.json|g" \
    -e 's/^    main "\$@"$/    configure_docker_dns/' \
    "$REPO_ROOT/secure-server.sh" >"$TEST_ROOT/secure-server.sh"
chmod 0700 "$TEST_ROOT/secure-server.sh"

make_mock() {
    local name="$1" body="$2"
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' "$body" >"$TEST_ROOT/bin/$name"
    chmod 0700 "$TEST_ROOT/bin/$name"
}

make_mock docker 'exit 0'
make_mock dockerd '
[[ "${1:-}" == --validate ]] || exit 64
python3 -m json.tool "${3:-}" >/dev/null'
make_mock install '
if [[ "${1:-}" == -d ]]; then
  while (( $# )); do
    case "$1" in -o|-g|-m) shift ;; -d|-*) ;; *) mkdir -p -- "$1" ;; esac
    shift
  done
  exit 0
fi
exit 64'
make_mock chown 'exit 0'

PATH="$TEST_ROOT/bin:$PATH" "$TEST_ROOT/secure-server.sh" || fail 'configuracao inicial falhou'

python3 - "$TEST_ROOT/docker/daemon.json" <<'PY' || fail 'daemon.json nao preservou opcoes nem definiu DNS'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
assert config["dns"] == ["1.1.1.1", "8.8.8.8"]
assert config["log-driver"] == "json-file"
assert config["log-opts"] == {"max-size": "10m"}
PY

# A segunda execucao nao deve regravar nem sinalizar mudanca.
if PATH="$TEST_ROOT/bin:$PATH" "$TEST_ROOT/secure-server.sh"; then
    fail 'segunda execucao deveria indicar que daemon.json ja esta atual'
fi

printf 'PASS: docker daemon DNS defaults\n'
