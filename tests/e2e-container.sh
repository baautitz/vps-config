#!/usr/bin/env bash
# Teste ponta a ponta em containers privilegiados com systemd, sshd, Fail2Ban e
# Docker reais; clientes em outros containers veem o firewall "de fora".
# Nao cobre boot real, kernel do Ubuntu nem imagens cloud.
# Uso: tests/e2e-container.sh [versao...]   (padrao: 22.04 24.04 26.04)
set -uo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SCRIPT="${SECURE_E2E_SCRIPT:-${REPO_ROOT}/secure-server.sh}"
readonly NET="secure-e2e"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/secure-e2e.XXXXXX")"
FAILURES=0
CONTAINERS=()

cleanup() {
    if (( ${#CONTAINERS[@]} )); then
        podman rm -f -t 1 "${CONTAINERS[@]}" >/dev/null 2>&1
    fi
    podman network rm "$NET" >/dev/null 2>&1
    rm -rf -- "$WORK"
}
trap cleanup EXIT

check() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '  PASS  %s\n' "$description"
    else
        printf '  FAIL  %s\n' "$description"
        FAILURES=$((FAILURES + 1))
    fi
}

check_not() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '  FAIL  %s\n' "$description"
        FAILURES=$((FAILURES + 1))
    else
        printf '  PASS  %s\n' "$description"
    fi
}

on() {
    local name="$1"
    shift
    podman exec "$name" bash -c "$*"
}

build_image() {
    local version="$1" dir="${WORK}/img-${version}"
    mkdir -p "$dir"
    cat >"${dir}/Containerfile" <<EOF
FROM docker.io/library/ubuntu:${version}
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus docker.io iproute2 openssh-client openssh-server python3 iptables ufw >/dev/null
RUN mkdir -p /etc/docker && printf '{"storage-driver":"vfs","features":{"containerd-snapshotter":false}}\n' >/etc/docker/daemon.json
CMD ["/sbin/init"]
EOF
    podman build -q -t "secure-e2e:${version}" "$dir" >/dev/null
}

start() {
    local name="$1" version="$2"
    CONTAINERS+=("$name")
    podman run -d --name "$name" --hostname "$name" --network "$NET" --privileged --systemd=always "secure-e2e:${version}" >/dev/null
    local attempt
    for attempt in $(seq 60); do
        on "$name" 'systemctl is-active docker' >/dev/null 2>&1 && break
        sleep 2
    done
    podman cp "${WORK}/key.pub" "${name}:/root/.ssh/authorized_keys" 2>/dev/null || {
        on "$name" 'install -d -m 0700 /root/.ssh'
        podman cp "${WORK}/key.pub" "${name}:/root/.ssh/authorized_keys"
    }
    podman cp "${WORK}/key" "${name}:/root/test-key"
    on "$name" 'chmod 700 /root /root/.ssh; chown -R root:root /root/.ssh; chmod 600 /root/.ssh/authorized_keys /root/test-key; chown root:root /root/test-key'
    podman cp "$SCRIPT" "${name}:/root/secure-server.sh"
    on "$name" 'chmod 700 /root/secure-server.sh'
}

ip_of() {
    podman inspect -f "{{(index .NetworkSettings.Networks \"${NET}\").IPAddress}}" "$1"
}

port_open() {
    local client="$1" address="$2" port="$3"
    on "$client" "timeout 3 bash -c '</dev/tcp/${address}/${port}'"
}

ssh_ok() {
    local client="$1" address="$2"
    on "$client" "ssh -i /root/test-key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@${address} true"
}

password_refused() {
    local client="$1" address="$2" output
    output="$(on "$client" "ssh -o BatchMode=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o NumberOfPasswordPrompts=0 root@${address} true 2>&1")"
    [[ "$output" == *'Permission denied'* && "$output" != *password,* && "$output" != *',password'* ]]
}

aborts_without_changes() {
    local name="$1" expected="$2" output
    if output="$(on "$name" '/root/secure-server.sh install 2>&1')"; then
        return 1
    fi
    [[ "$output" == *"$expected"* ]] || return 1
    on "$name" '[ ! -e /etc/ssh/sshd_config.d/00-secure-server.conf ] && [ ! -e /etc/systemd/system/secure-host-firewall.service ]'
}

scenario_validations() {
    local version="$1" name="val-${version//./}"
    printf '[%s] validacoes antes de alterar\n' "$version"
    start "$name" "$version"
    on "$name" "sed -i 's/^/command=\"echo Please login as ubuntu\" /' /root/.ssh/authorized_keys"
    check 'aborta com chave restrita por command=' aborts_without_changes "$name" 'command='
    podman cp "${WORK}/key.pub" "${name}:/root/.ssh/authorized_keys"
    on "$name" 'chown root:root /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys'
    on "$name" 'echo "Port 2222" >/etc/ssh/sshd_config.d/01-port.conf'
    check 'aborta com porta SSH customizada' aborts_without_changes "$name" 'porta'
    on "$name" 'unlink /etc/ssh/sshd_config.d/01-port.conf'
    on "$name" 'ip link add br-pub type bridge && ip link set br-pub up && ip route replace default dev br-pub'
    check 'aborta com rota padrao em br-*' aborts_without_changes "$name" 'rota padrao'
}

scenario_rollback() {
    local version="$1" name="rb-${version//./}"
    printf '[%s] rollback\n' "$version"
    start "$name" "$version"
    on "$name" 'echo marcador >/etc/ufw/marcador-e2e; iptables -N PRE-E2E; iptables -A INPUT -p tcp --dport 9999 -j PRE-E2E; iptables -S | grep -v -E "^-[NA] DOCKER|^-A FORWARD" | sort >/root/before.rules'
    # Falha real depois das mutacoes: passa por die, nao pelo trap ERR.
    on "$name" 'mv /etc/fail2ban/action.d/iptables-multiport.conf /root/ 2>/dev/null; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban python3-systemd conntrack >/dev/null; mv /etc/fail2ban/action.d/iptables-multiport.conf /root/'
    check_not 'install falha' on "$name" '/root/secure-server.sh install'
    check 'regras restauradas' on "$name" 'iptables -S | grep -v -E "^-[NA] DOCKER|^-A FORWARD" | sort | diff - /root/before.rules'
    check 'drop-in SSH removido' on "$name" '[ ! -e /etc/ssh/sshd_config.d/00-secure-server.conf ]'
    check 'unit do firewall removida' on "$name" '[ ! -e /etc/systemd/system/secure-host-firewall.service ] && ! systemctl is-enabled secure-host-firewall'
    check 'drop-in Docker removido' on "$name" '[ ! -e /etc/systemd/system/docker.service.d/10-secure-firewall.conf ]'
    check 'ufw reinstalado com configuracao' on "$name" 'dpkg-query -W -f="\${db:Status-Status}" ufw | grep -qx installed && grep -q marcador /etc/ufw/marcador-e2e'
    check 'Docker segue ativo' on "$name" 'systemctl is-active docker'
}

scenario_main() {
    local version="$1" suffix="${1//./}"
    local target="srv-${suffix}" client="cli-${suffix}" attacker="atk-${suffix}" address
    printf '[%s] install, SSH, firewall, Docker, Fail2Ban\n' "$version"
    start "$target" "$version"
    start "$client" "$version"
    start "$attacker" "$version"
    address="$(ip_of "$target")"

    check 'container de teste sobe' on "$target" 'docker pull -q docker.io/library/busybox && docker run -d --restart=always -p 80:8000 -p 5400:8000 busybox httpd -f -p 8000'
    check 'estado inicial: porta Docker 5400 exposta' port_open "$client" "$address" 5400

    check 'install conclui' on "$target" '/root/secure-server.sh install'
    check 'install repetido conclui' on "$target" '/root/secure-server.sh install'
    check 'ufw removido' on "$target" '! dpkg-query -W -f="\${db:Status-Status}" ufw | grep -qx installed'
    check 'nova conexao SSH por chave' ssh_ok "$client" "$address"
    check 'login por senha recusado' password_refused "$client" "$address"
    check 'Docker 80 acessivel' port_open "$client" "$address" 80
    check_not 'Docker 5400 bloqueada' port_open "$client" "$address" 5400
    check_not 'host 9000 bloqueada' port_open "$client" "$address" 9000

    check 'open-port 5400' on "$target" '/root/secure-server.sh open-port 5400'
    check 'Docker 5400 acessivel apos open-port' port_open "$client" "$address" 5400
    check 'close-port 5400' on "$target" '/root/secure-server.sh close-port 5400'
    check_not 'Docker 5400 bloqueada apos close-port' port_open "$client" "$address" 5400
    check_not 'close-port 80 recusado' on "$target" '/root/secure-server.sh close-port 80'
    check 'Docker 80 segue acessivel' port_open "$client" "$address" 80

    # Reinicio do Docker: a porta bloqueada nunca pode responder durante a janela.
    on "$client" "timeout 25 bash -c 'n=0; while true; do if timeout 1 bash -c \"</dev/tcp/${address}/5400\" 2>/dev/null; then n=\$((n+1)); fi; sleep 0.1; echo \$n >/root/hits; done'" >/dev/null 2>&1 &
    local prober=$!
    sleep 2
    on "$target" 'systemctl restart docker'
    wait "$prober"
    check 'sem exposicao de 5400 ao reiniciar Docker' on "$client" '[ "$(cat /root/hits)" = 0 ]'
    check 'Docker 80 volta apos reinicio' port_open "$client" "$address" 80

    local attempt
    for attempt in 1 2 3 4 5; do
        on "$attacker" "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 nobody@${address} true" >/dev/null 2>&1
    done
    sleep 8
    check 'Fail2Ban registrou o ban' on "$target" "fail2ban-client status sshd | grep -q '$(ip_of "$attacker")'"
    check_not 'atacante bloqueado na porta 22' port_open "$attacker" "$address" 22
    check 'open-port 7000 com ban ativo' on "$target" '/root/secure-server.sh open-port 7000'
    check_not 'ban continua valendo apos open-port' port_open "$attacker" "$address" 22
    check 'cliente legitimo nao foi banido' ssh_ok "$client" "$address"

    printf '[%s] reinicio do container\n' "$version"
    podman restart -t 5 "$target" >/dev/null
    for attempt in $(seq 60); do
        on "$target" 'systemctl is-active docker' >/dev/null 2>&1 && break
        sleep 2
    done
    sleep 8
    address="$(ip_of "$target")"
    check 'unit do firewall ativa' on "$target" 'systemctl is-active secure-host-firewall'
    check 'politica INPUT DROP' on "$target" 'iptables -S INPUT | grep -qx -- "-P INPUT DROP"'
    check 'salto VPS-DOCKER no topo' on "$target" 'iptables -S DOCKER-USER | sed -n 2p | grep -q VPS-DOCKER'
    check 'SSH apos reinicio' ssh_ok "$client" "$address"
    check 'porta aberta persistiu' on "$target" 'iptables -S INPUT | grep -q -- "--dport 7000"'
    check_not 'Docker 5400 bloqueada apos reinicio' port_open "$client" "$address" 5400
}

main() {
    local versions=("$@") version
    (( ${#versions[@]} )) || versions=(22.04 24.04 26.04)
    ssh-keygen -q -t ed25519 -N '' -C e2e -f "${WORK}/key"
    podman network create "$NET" >/dev/null
    for version in "${versions[@]}"; do
        build_image "$version" || { printf 'FAIL: imagem %s\n' "$version"; FAILURES=$((FAILURES + 1)); continue; }
        scenario_validations "$version"
        scenario_rollback "$version"
        scenario_main "$version"
        podman rm -f -t 1 "${CONTAINERS[@]}" >/dev/null 2>&1
        CONTAINERS=()
    done
    if (( FAILURES )); then
        printf 'FAIL: %d verificacao(oes)\n' "$FAILURES"
        exit 1
    fi
    printf 'PASS: e2e em %s\n' "${versions[*]}"
}

main "$@"
