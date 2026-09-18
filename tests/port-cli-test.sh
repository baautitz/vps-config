#!/usr/bin/env bash
# Testes de integracao seguros para a CLI de portas. Nenhum comando toca no
# firewall real: o alvo e uma copia temporaria com iptables, systemctl e docker
# simulados no PATH.
set -Eeuo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SOURCE_SCRIPT="${REPO_ROOT}/secure-efa-server.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/secure-efa-port-test.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local expected="$1" file="$2"
    grep -Fqx -- "$expected" "$file" >/dev/null || fail "nao encontrou em ${file}: ${expected}"
}

assert_not_contains() {
    local unexpected="$1" file="$2"
    if grep -Fqx -- "$unexpected" "$file" >/dev/null; then
        fail "encontrou indevidamente em ${file}: ${unexpected}"
    fi
}

assert_count() {
    local expected_count="$1" expected="$2" file="$3" actual
    actual="$(grep -Fxc -- "$expected" "$file" || true)"
    [[ "$actual" == "$expected_count" ]] || fail "${file}: esperado ${expected_count} ocorrencia(s) de '${expected}', obteve ${actual}"
}

assert_entry() {
    local port="$1" proto="$2" scope="$3" file="$4"
    awk -F '\t' -v port="$port" -v proto="$proto" -v scope="$scope" \
        '$1 == port && $2 == proto && $3 == scope { found = 1 } END { exit !found }' "$file" \
        || fail "nao encontrou entrada ${port}/${proto} no escopo ${scope} em ${file}"
}

assert_no_entry() {
    local port="$1" proto="$2" scope="$3" file="$4"
    if awk -F '\t' -v port="$port" -v proto="$proto" -v scope="$scope" \
        '$1 == port && $2 == proto && $3 == scope { found = 1 } END { exit found ? 0 : 1 }' "$file"; then
        fail "encontrou indevidamente entrada ${port}/${proto} no escopo ${scope} em ${file}"
    fi
}

assert_before() {
    local first="$1" second="$2" file="$3" first_line second_line
    first_line="$(grep -Fn -- "$first" "$file" | head -n1 | cut -d: -f1)"
    second_line="$(grep -Fn -- "$second" "$file" | head -n1 | cut -d: -f1)"
    [[ -n "$first_line" && -n "$second_line" && "$first_line" -lt "$second_line" ]] \
        || fail "ordem incorreta em ${file}: '${first}' precisa vir antes de '${second}'"
}

make_mock() {
    local name="$1"
    shift
    apply_mock_content="$*"
    # shellcheck disable=SC2016
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' "$apply_mock_content" >"${TEST_ROOT}/bin/${name}"
    chmod 0700 "${TEST_ROOT}/bin/${name}"
}

prepare_target() {
    mkdir -p "${TEST_ROOT}/bin" "${TEST_ROOT}/iptables" "${TEST_ROOT}/backups" "${TEST_ROOT}/lock"
    # O unico desvio da copia testada e a verificacao de UID: testes nao
    # privilegiam o processo, apenas redirecionam todos os caminhos mutaveis.
    sed \
        -e "s|/etc/iptables|${TEST_ROOT}/iptables|g" \
        -e "s|/var/backups/secure-efa-server|${TEST_ROOT}/backups|g" \
        -e "s|/run/lock/secure-efa-server.lock|${TEST_ROOT}/lock/secure-efa-server.lock|g" \
        -e 's/(( EUID == 0 )) || die /true || die /g' \
        "$SOURCE_SCRIPT" >"${TEST_ROOT}/secure-efa-server.sh"
    chmod 0700 "${TEST_ROOT}/secure-efa-server.sh"

    # Arquivos que indicam que o install ja foi executado; conteudo minimo e
    # valido para o gerador substituir durante open/close.
    printf '*filter\nCOMMIT\n' >"${TEST_ROOT}/iptables/secure-efa-host.v4"
    printf '*filter\nCOMMIT\n' >"${TEST_ROOT}/iptables/secure-efa-host.v6"
    printf '*filter\nCOMMIT\n' >"${TEST_ROOT}/iptables/secure-efa-docker.v4"
    printf '*filter\nCOMMIT\n' >"${TEST_ROOT}/iptables/secure-efa-docker.v6"

    make_mock systemctl '
case "${1:-}" in
  is-active) [[ "${2:-}" == docker ]] && exit 0; exit 3 ;;
  *) exit 0 ;;
esac'
    make_mock docker '
if [[ "${1:-}" == ps ]]; then
  printf "%s\\n" "${SECURE_EFA_TEST_DOCKER_PS:-}"
fi'
    # O script usa `install` para criar diretórios e publicar arquivos de
    # regras atomicamente. O mock mantém só essas semânticas; ignora ownership
    # e modo porque o teste intencionalmente não tem privilégios de root.
    make_mock install '
is_directory=0
paths=()
while (( $# )); do
  case "$1" in
    -d) is_directory=1 ;;
    -o|-g|-m) shift ;;
    --) shift; break ;;
    -*) ;;
    *) paths+=("$1") ;;
  esac
  shift
done
while (( $# )); do paths+=("$1"); shift; done
if (( is_directory )); then
  mkdir -p -- "${paths[@]}"
else
  [[ "${#paths[@]}" == 2 ]] || exit 64
  cp -- "${paths[0]}" "${paths[1]}"
fi'
    make_mock iptables '
printf "iptables %s\\n" "$*" >>"$SECURE_EFA_TEST_LOG"
[[ "${1:-}" == -S ]] && exit 0
[[ "${1:-}" == -D ]] && exit 1
exit 0'
    make_mock ip6tables '
printf "ip6tables %s\\n" "$*" >>"$SECURE_EFA_TEST_LOG"
[[ "${1:-}" == -S ]] && exit 0
[[ "${1:-}" == -D ]] && exit 1
exit 0'
    make_mock iptables-restore '
cat >/dev/null
printf "iptables-restore %s\\n" "$*" >>"$SECURE_EFA_TEST_LOG"'
    make_mock ip6tables-restore '
cat >/dev/null
printf "ip6tables-restore %s\\n" "$*" >>"$SECURE_EFA_TEST_LOG"'
    make_mock conntrack '
printf "conntrack %s\\n" "$*" >>"$SECURE_EFA_TEST_LOG"
exit 0'
}

run_cli() {
    local output
    output="$(PATH="${TEST_ROOT}/bin:${PATH}" SECURE_EFA_TEST_LOG="${TEST_ROOT}/commands.log" \
        SECURE_EFA_TEST_DOCKER_PS='abc123|redis|0.0.0.0:6379->6379/tcp' \
        "${TEST_ROOT}/secure-efa-server.sh" "$@" 2>&1)" || {
        printf '%s\n' "$output" >&2
        fail "comando falhou: $*"
    }
    printf '%s\n' "$output"
}

test_no_args_shows_help() {
    local output
    output="$(run_cli)"
    [[ "$output" == *'Uso: sudo ./secure-efa-server.sh <comando> [args]'* ]] \
        || fail 'executar sem subcomando nao exibiu a ajuda'
}

test_open_is_idempotent_and_covers_both_scopes() {
    local allowed="${TEST_ROOT}/iptables/secure-efa-allowed-ports.list"
    run_cli open-port 6379 >/dev/null

    # Uma porta publicada pelo Docker deve liberar o host e a cadeia Docker;
    # assim uma mudanca de publicacao nao deixa uma das camadas divergente.
    assert_entry 6379 tcp host "$allowed"
    assert_entry 6379 tcp docker "$allowed"
    assert_contains '-A INPUT -p tcp -m conntrack --ctstate NEW -m multiport --dports 22,80,443 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-host.v4"
    assert_contains '-A INPUT -i docker0 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-host.v4"
    assert_contains '-A INPUT -i br+ -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-host.v4"
    assert_contains '-A INPUT -i docker_gwbridge -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-host.v4"
    assert_contains '-A EFA-DOCKER -i docker_gwbridge -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-docker.v4"
    assert_contains '-A EFA-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 80 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-docker.v4"
    assert_contains '-A EFA-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 443 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-docker.v4"
    assert_contains '-A INPUT -p tcp -m conntrack --ctstate NEW --dport 6379 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-host.v4"
    assert_contains '-A EFA-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 6379 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-docker.v4"
    assert_before \
        '-A EFA-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 6379 -j ACCEPT' \
        '-A EFA-DOCKER-ALLOW -j RETURN' \
        "${TEST_ROOT}/iptables/secure-efa-docker.v4"

    run_cli open-port 6379 >/dev/null
    [[ "$(awk -F '\t' '$1 == 6379 && $2 == "tcp" && $3 == "host" { count++ } END { print count + 0 }' "$allowed")" == 1 ]] || fail 'open duplicou a entrada host'
    [[ "$(awk -F '\t' '$1 == 6379 && $2 == "tcp" && $3 == "docker" { count++ } END { print count + 0 }' "$allowed")" == 1 ]] || fail 'open duplicou a entrada Docker'
}

test_close_removes_both_scopes_and_stale_rules() {
    local allowed="${TEST_ROOT}/iptables/secure-efa-allowed-ports.list"
    run_cli close-port 6379 >/dev/null
    assert_no_entry 6379 tcp host "$allowed"
    assert_no_entry 6379 tcp docker "$allowed"
    ! grep -F -- '--dport 6379 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-host.v4" >/dev/null || fail 'regra host continuou no arquivo regenerado'
    ! grep -F -- '--ctorigdstport 6379 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-docker.v4" >/dev/null || fail 'regra Docker continuou no arquivo regenerado'
    assert_contains 'conntrack -D -f ipv4 -p tcp --orig-port-dst 6379' "${TEST_ROOT}/commands.log"
    assert_contains 'conntrack -D -f ipv6 -p tcp --orig-port-dst 6379' "${TEST_ROOT}/commands.log"
}

test_udp_and_legacy_state_are_reconciled() {
    local allowed="${TEST_ROOT}/iptables/secure-efa-allowed-ports.list"
    run_cli open-port 5353/udp >/dev/null
    assert_entry 5353 udp host "$allowed"
    assert_entry 5353 udp docker "$allowed"
    assert_contains '-A INPUT -p udp -m conntrack --ctstate NEW --dport 5353 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-host.v6"
    assert_contains '-A EFA-DOCKER-ALLOW -p udp -m conntrack --ctstate NEW --ctorigdstport 5353 -j ACCEPT' "${TEST_ROOT}/iptables/secure-efa-docker.v6"
    run_cli close-port 5353/udp >/dev/null
    assert_no_entry 5353 udp host "$allowed"
    assert_no_entry 5353 udp docker "$allowed"

    # A versao com defeito gravou a sequencia literal "\\t". O close deve
    # compreender esse estado antigo e removê-lo, evitando uma porta órfã.
    printf '%s\n' \
        '# Gerenciado por secure-efa-server.sh (open-port / close-port).' \
        '# Formato: <porta>\t<proto>\t<escopo>\t<origem>' \
        '5400\ttcp\tdocker\tdocker:container-a' \
        '6380\ttcp\tdocker\tdocker:container-b' >"$allowed"
    run_cli close-port 6380 >/dev/null
    assert_no_entry 6380 tcp docker "$allowed"
    assert_entry 5400 tcp docker "$allowed"
    ! grep -F '6380\ttcp\tdocker\tdocker:container-b' "$allowed" >/dev/null || fail 'entrada legada literal permaneceu no estado canonico'
    ! grep -F '5400\ttcp\tdocker\tdocker:container-a' "$allowed" >/dev/null || fail 'estado legado remanescente nao foi normalizado para TAB real'
}

main() {
    prepare_target
    test_no_args_shows_help
    test_open_is_idempotent_and_covers_both_scopes
    test_close_removes_both_scopes_and_stale_rules
    test_udp_and_legacy_state_are_reconciled
    printf 'PASS: port CLI host+docker lifecycle\n'
}

main "$@"
