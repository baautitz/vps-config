#!/usr/bin/env bash

# Hardening simples para Ubuntu 22.04/24.04/26.04 com SSH, Fail2Ban e iptables.
# Docker continua dono do NAT/publicacao; este script usa DOCKER-USER.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_NAME="${0##*/}"
readonly BACKUP_BASE="/var/backups/secure-server"
readonly LOCK_FILE="/run/lock/secure-server.lock"
readonly AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
readonly SSH_DROPIN="/etc/ssh/sshd_config.d/00-secure-server.conf"
readonly F2B_JAIL="/etc/fail2ban/jail.local"
readonly F2B_LEGACY_JAIL="/etc/fail2ban/jail.d/sshd.local"
readonly IPTABLES_DIR="/etc/iptables"
readonly HOST_V4="${IPTABLES_DIR}/secure-host.v4"
readonly HOST_V6="${IPTABLES_DIR}/secure-host.v6"
readonly DOCKER_V4="${IPTABLES_DIR}/secure-docker.v4"
readonly DOCKER_V6="${IPTABLES_DIR}/secure-docker.v6"
readonly DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
readonly HOST_UNIT="/etc/systemd/system/secure-host-firewall.service"
readonly DOCKER_DROPIN="/etc/systemd/system/docker.service.d/10-secure-firewall.conf"
readonly PORT_MARKER_BEGIN="# BEGIN secure-server managed ports"
readonly PORT_MARKER_END="# END secure-server managed ports"
readonly ALLOWED_PORTS_FILE="${IPTABLES_DIR}/secure-allowed-ports.list"
readonly BACKUP_OPEN_BASE="/var/backups/secure-server/open-port"

BACKUP_DIR=""
MUTATIONS_STARTED=0
ROLLBACK_RUNNING=0
SUCCESS=0
SSH_WAS_ACTIVE=0
SSH_WAS_ENABLED=0
F2B_WAS_ACTIVE=0
F2B_WAS_ENABLED=0
UFW_WAS_ACTIVE=0
UFW_WAS_ENABLED=0
UFW_WAS_INSTALLED=0
HOST_FW_WAS_ENABLED=0
DOCKER_WAS_ACTIVE=0
DOCKER_RESTARTED=0

log() {
    local level="$1"
    shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" >&2
}

die() {
    log ERRO "$*"
    exit 1
}

show_help() {
    cat <<EOF
Uso: sudo ./${SCRIPT_NAME} <comando> [args]

Subcomandos:
  install                       Configura o servidor (idempotente).
  open-port <PORTA>[/udp]       Abre uma porta no host e no Docker; persiste no boot.
  close-port <PORTA>[/udp]      Fecha uma porta no host e no Docker.
  list-ports [--docker|--host]  Lista portas liberadas (canonicas).
  help                          Mostra este texto.

Execute 'sudo ./${SCRIPT_NAME} help' para exemplos.
EOF
}

service_is_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

service_is_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

permissions_are_safe() {
    local path="$1" owner mode
    owner="$(stat -c '%u' "$path")"
    mode="$(stat -c '%a' "$path")"
    [[ "$owner" == 0 ]] && (( ((8#${mode}) & 0022) == 0 ))
}

validate_platform() {
    [[ "$EUID" -eq 0 ]] || die "Execute como root: sudo ./${SCRIPT_NAME}"
    [[ -r /etc/os-release ]] || die "Nao foi possivel identificar o sistema."
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == ubuntu ]] || die "Sistema nao suportado: esperado Ubuntu."
    case "${VERSION_ID:-}" in
        22.04|24.04|26.04) ;;
        *) die "Versao nao suportada: use Ubuntu 22.04, 24.04 ou 26.04." ;;
    esac
    [[ -d /run/systemd/system ]] || die "O sistema precisa usar systemd."
}

validate_authorized_keys() {
    [[ -d /root/.ssh && ! -L /root/.ssh ]] || die "/root/.ssh nao existe ou e link simbolico."
    [[ -f "$AUTHORIZED_KEYS" && ! -L "$AUTHORIZED_KEYS" && -s "$AUTHORIZED_KEYS" ]] || die "${AUTHORIZED_KEYS} nao existe, e invalido ou esta vazio."
    permissions_are_safe /root || die "/root tem permissoes inseguras."
    permissions_are_safe /root/.ssh || die "/root/.ssh tem permissoes inseguras."
    permissions_are_safe "$AUTHORIZED_KEYS" || die "${AUTHORIZED_KEYS} tem permissoes inseguras."
    ssh-keygen -l -f "$AUTHORIZED_KEYS" >/dev/null 2>&1 || die "Nenhuma chave publica valida em ${AUTHORIZED_KEYS}."
    # Imagens cloud costumam prefixar a chave do root com command="echo Please
    # login as..."; com AllowUsers root, isso impediria qualquer acesso.
    has_usable_root_key || die "${AUTHORIZED_KEYS} so tem chaves com command=; adicione uma chave de login direto para o root."
}

has_usable_root_key() {
    grep -Ev '^[[:space:]]*(#|$)' "$AUTHORIZED_KEYS" | grep -v 'command=' | ssh-keygen -l -f - >/dev/null 2>&1
}

# O firewall so libera a porta 22: outra porta significaria perder o acesso.
validate_ssh_port() {
    local config ports listen
    install -d -o root -g root -m 0755 /run/sshd
    config="$(sshd -T)" || die "Nao foi possivel ler a configuracao efetiva do sshd."
    ports="$(awk '$1 == "port" { print $2 }' <<<"$config")"
    [[ "$ports" == 22 ]] || die "SSH configurado em outra porta ($(tr '\n' ' ' <<<"$ports")); este script exige somente a porta 22."
    if service_is_active ssh.socket; then
        listen="$(systemctl show ssh.socket -p Listen --value)"
        if grep -v ':22 ' <<<"$listen" | grep -q .; then
            die "ssh.socket escuta fora da porta 22; este script exige somente a porta 22."
        fi
    fi
}

verify_ssh_effective() {
    local config expected
    config="$(sshd -T)" || die "Nao foi possivel ler a configuracao efetiva do sshd."
    for expected in 'port 22' 'permitrootlogin (prohibit-password|without-password)' \
        'passwordauthentication no' 'kbdinteractiveauthentication no' \
        'authenticationmethods publickey' 'allowusers root'; do
        grep -Eqx "$expected" <<<"$config" || die "Configuracao efetiva do sshd difere do esperado: ${expected}."
    done
}

# Com ipv6.disable=1 o kernel nao tem a pilha IPv6 e ip6tables falharia.
ipv6_available() {
    [[ -e /proc/net/if_inet6 ]]
}

# As regras de bridge confiam em docker0, br-* e docker_gwbridge: se a interface
# publica tiver um desses nomes, a Internet seria tratada como trafego interno.
validate_public_interface() {
    command -v ip >/dev/null || die "ip nao foi encontrado. Instale o pacote iproute2."
    local family dev
    for family in -4 -6; do
        while IFS= read -r dev; do
            case "$dev" in
                docker0|docker_gwbridge|br-*) die "A rota padrao usa ${dev}, nome reservado as bridges do Docker; o firewall nao seria seguro." ;;
            esac
        done < <(ip "$family" route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }')
    done
}

package_is_installed() {
    dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -qx installed
}

purge_ufw() {
    log INFO "Removendo o pacote ufw (iptables e a fonte unica de verdade)."
    systemctl disable --now ufw >/dev/null 2>&1 || true
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y -o Dpkg::Options::=--force-confold ufw || return 1
    rm -rf -- /etc/ufw
    return 0
}

reinstall_ufw() {
    log INFO "Reinstalando o pacote ufw (rollback)."
    apt-get update >/dev/null 2>&1 || return 1
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -o Dpkg::Options::=--force-confold ufw || return 1
    return 0
}

ensure_packages() {
    local package
    local -a missing=()
    for package in openssh-server fail2ban python3-systemd iptables conntrack; do
        package_is_installed "$package" || missing+=("$package")
    done
    if (( ${#missing[@]} )); then
        log INFO "Instalando: ${missing[*]}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y -o Dpkg::Options::=--force-confold "${missing[@]}"
    fi
}

validate_firewall_environment() {
    command -v iptables >/dev/null || die "iptables nao foi encontrado. Instale o pacote iptables."
    command -v iptables-restore >/dev/null || die "iptables-restore nao foi encontrado. Instale o pacote iptables."
    command -v ip6tables >/dev/null || die "ip6tables nao foi encontrado. Instale o pacote iptables."
    command -v ip6tables-restore >/dev/null || die "ip6tables-restore nao foi encontrado. Instale o pacote iptables."

    local active_services=()
    if service_is_active firewalld; then active_services+=("firewalld(active)"); fi
    if service_is_enabled firewalld; then active_services+=("firewalld(enabled)"); fi
    if service_is_active nftables; then active_services+=("nftables(active)"); fi
    if service_is_enabled nftables; then active_services+=("nftables(enabled)"); fi
    if (( ${#active_services[@]} )); then
        die "Outro firewall ja controla o sistema: ${active_services[*]}. Desative antes (systemctl disable --now ...)."
    fi

    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        if grep -Eq '"iptables"[[:space:]]*:[[:space:]]*false' "$DOCKER_DAEMON_JSON"; then
            die "${DOCKER_DAEMON_JSON} define iptables=false; remova essa opcao e reinicie o Docker."
        fi
        if grep -Eq '"firewall-backend"[[:space:]]*:[[:space:]]*"nftables"' "$DOCKER_DAEMON_JSON"; then
            die "${DOCKER_DAEMON_JSON} define firewall-backend=nftables; este script exige o backend iptables."
        fi
    fi
}

capture_initial_state() {
    service_is_active ssh && SSH_WAS_ACTIVE=1 || true
    service_is_enabled ssh && SSH_WAS_ENABLED=1 || true
    service_is_active fail2ban && F2B_WAS_ACTIVE=1 || true
    service_is_enabled fail2ban && F2B_WAS_ENABLED=1 || true
    service_is_active ufw && UFW_WAS_ACTIVE=1 || true
    service_is_enabled ufw && UFW_WAS_ENABLED=1 || true
    package_is_installed ufw && UFW_WAS_INSTALLED=1 || true
    service_is_enabled secure-host-firewall && HOST_FW_WAS_ENABLED=1 || true
    service_is_active docker && DOCKER_WAS_ACTIVE=1 || true
}

prepare_backup_dir() {
    BACKUP_DIR="${BACKUP_BASE}/$(date -u '+%Y%m%dT%H%M%S.%NZ')"
    install -d -o root -g root -m 0700 "$BACKUP_DIR/items"
    cat >"${BACKUP_DIR}/initial-state" <<EOF
ssh_active=${SSH_WAS_ACTIVE}
ssh_enabled=${SSH_WAS_ENABLED}
fail2ban_active=${F2B_WAS_ACTIVE}
fail2ban_enabled=${F2B_WAS_ENABLED}
ufw_active=${UFW_WAS_ACTIVE}
ufw_enabled=${UFW_WAS_ENABLED}
ufw_installed=${UFW_WAS_INSTALLED}
EOF
    chmod 0600 "${BACKUP_DIR}/initial-state"
}

backup_item() {
    local path="$1" label="$2"
    if [[ -e "$path" || -L "$path" ]]; then
        printf 'present\n' >"${BACKUP_DIR}/items/${label}.state"
        cp -a -- "$path" "${BACKUP_DIR}/items/${label}"
    else
        printf 'absent\n' >"${BACKUP_DIR}/items/${label}.state"
    fi
}

restore_item() {
    local path="$1" label="$2" state="${BACKUP_DIR}/items/${2}.state"
    [[ -f "$state" ]] || return 0
    if grep -qx present "$state"; then
        rm -rf -- "$path"
        cp -a -- "${BACKUP_DIR}/items/${label}" "$path"
    else
        rm -f -- "$path"
    fi
}

backup_configuration() {
    backup_item /etc/ssh/sshd_config sshd-config
    backup_item "$SSH_DROPIN" ssh-dropin
    backup_item "$F2B_JAIL" fail2ban-jail
    backup_item "$F2B_LEGACY_JAIL" fail2ban-legacy-jail
    backup_item "$HOST_V4" host-v4
    backup_item "$HOST_V6" host-v6
    backup_item "$DOCKER_V4" docker-v4
    backup_item "$DOCKER_V6" docker-v6
    backup_item "$DOCKER_DAEMON_JSON" docker-daemon-json
    backup_item "$HOST_UNIT" host-unit
    backup_item "$DOCKER_DROPIN" docker-dropin
    backup_item /etc/ufw ufw-config
    iptables-save >"${BACKUP_DIR}/iptables.v4"
    chmod 0600 "${BACKUP_DIR}/iptables.v4"
    if ipv6_available; then
        ip6tables-save >"${BACKUP_DIR}/iptables.v6"
        chmod 0600 "${BACKUP_DIR}/iptables.v6"
    fi
}

restore_enabled_state() {
    local service="$1" enabled="$2"
    if (( enabled )); then
        systemctl enable "$service" >/dev/null 2>&1 || true
    else
        systemctl disable "$service" >/dev/null 2>&1 || true
    fi
}

rollback() {
    local failed=0
    (( ROLLBACK_RUNNING == 0 )) || return 0
    ROLLBACK_RUNNING=1
    set +e
    log AVISO "Falha detectada; restaurando configuracoes e regras anteriores."

    systemctl stop fail2ban >/dev/null 2>&1 || true
    iptables-restore <"${BACKUP_DIR}/iptables.v4" || failed=1
    if [[ -f "${BACKUP_DIR}/iptables.v6" ]]; then
        ip6tables-restore <"${BACKUP_DIR}/iptables.v6" || failed=1
    fi
    restore_item /etc/ssh/sshd_config sshd-config || failed=1
    restore_item "$SSH_DROPIN" ssh-dropin || failed=1
    restore_item "$F2B_JAIL" fail2ban-jail || failed=1
    restore_item "$F2B_LEGACY_JAIL" fail2ban-legacy-jail || failed=1
    restore_item "$HOST_V4" host-v4 || failed=1
    restore_item "$HOST_V6" host-v6 || failed=1
    restore_item "$DOCKER_V4" docker-v4 || failed=1
    restore_item "$DOCKER_V6" docker-v6 || failed=1
    restore_item "$DOCKER_DAEMON_JSON" docker-daemon-json || failed=1
    (( HOST_FW_WAS_ENABLED )) || systemctl disable secure-host-firewall >/dev/null 2>&1 || true
    restore_item "$HOST_UNIT" host-unit || failed=1
    restore_item "$DOCKER_DROPIN" docker-dropin || failed=1
    systemctl daemon-reload >/dev/null 2>&1 || true

    if (( DOCKER_RESTARTED && DOCKER_WAS_ACTIVE )); then
        systemctl restart docker >/dev/null 2>&1 || failed=1
    fi

    if (( SSH_WAS_ACTIVE )); then
        sshd -t && systemctl restart ssh >/dev/null 2>&1 || failed=1
    else
        systemctl stop ssh >/dev/null 2>&1 || true
    fi
    restore_enabled_state ssh "$SSH_WAS_ENABLED"

    if (( UFW_WAS_INSTALLED )); then
        reinstall_ufw >/dev/null 2>&1 || failed=1
        restore_item /etc/ufw ufw-config || failed=1
        if (( UFW_WAS_ACTIVE )); then
            systemctl enable --now ufw >/dev/null 2>&1 || failed=1
        else
            systemctl disable --now ufw >/dev/null 2>&1 || true
        fi
        restore_enabled_state ufw "$UFW_WAS_ENABLED"
    fi

    if (( F2B_WAS_ACTIVE )); then
        systemctl start fail2ban >/dev/null 2>&1 || failed=1
    fi
    restore_enabled_state fail2ban "$F2B_WAS_ENABLED"

    if (( failed == 0 )); then
        log INFO "Reversao concluida. Backup: ${BACKUP_DIR}"
    else
        log ERRO "A reversao encontrou erros. Backup: ${BACKUP_DIR}"
    fi
    set -e
}

handle_error() {
    local status="$1" line="$2"
    # Com set -E o trap tambem dispara em subshells; so o processo principal reverte.
    (( BASHPID == $$ )) || exit "$status"
    trap - ERR INT TERM
    log ERRO "Comando falhou na linha ${line} (codigo ${status})."
    if (( MUTATIONS_STARTED && SUCCESS == 0 )); then
        rollback
    fi
    exit "$status"
}

# die encerra sem passar pelo trap ERR; EXIT garante a reversao nesses casos.
handle_exit() {
    local status="$?"
    trap - EXIT ERR INT TERM
    if (( status != 0 && MUTATIONS_STARTED && SUCCESS == 0 )); then
        rollback
    fi
    exit "$status"
}

handle_signal() {
    (( BASHPID == $$ )) || exit 130
    trap - ERR INT TERM
    log ERRO "Execucao interrompida."
    if (( MUTATIONS_STARTED && SUCCESS == 0 )); then
        rollback
    fi
    exit 130
}

write_atomic() {
    local path="$1" mode="$2" temporary
    install -d -o root -g root -m 0755 "$(dirname "$path")"
    temporary="$(mktemp "$(dirname "$path")/.${path##*/}.tmp.XXXXXX")"
    cat >"$temporary"
    chown root:root "$temporary"
    chmod "$mode" "$temporary"
    mv -f -- "$temporary" "$path"
}

# ---------- Utilitario de portas (open-port / close-port / list-ports) ----------

# Extrai a porta (1-65535) e o protocolo (tcp|udp) a partir de "PORTA",
# "PORTA/tcp" ou "PORTA/udp". Coloca o resultado em PROTO_OUT e PORT_OUT.
parse_port_spec() {
    local spec="$1" __proto_var="$2" __port_var="$3"
    local port_part="${spec%%/*}"
    local proto_part="${spec#*/}"
    if [[ "$spec" == */* ]]; then
        proto_part="${spec##*/}"
    else
        proto_part="tcp"
    fi
    if ! [[ "$port_part" =~ ^[0-9]+$ ]] || (( ${#port_part} > 5 )); then
        die "Porta invalida: '${spec}' (esperado 1-65535 ou 1-65535/tcp|udp)."
    fi
    local decimal_port=$((10#$port_part))
    if (( decimal_port < 1 || decimal_port > 65535 )); then
        die "Porta invalida: '${spec}' (esperado 1-65535 ou 1-65535/tcp|udp)."
    fi
    case "$proto_part" in
        tcp|udp) ;;
        *) die "Protocolo invalido em '${spec}': use tcp ou udp." ;;
    esac
    printf -v "$__proto_var" '%s' "$proto_part"
    printf -v "$__port_var" '%d' "$decimal_port"
}

# Carrega e valida o estado canônico. Versões anteriores gravavam "\\t"
# literal; essa leitura aceita o formato legado e qualquer gravação seguinte o
# normaliza para TAB real. Comentários e linhas inválidas nunca viram regras.
load_allowed_ports() {
    [[ -f "$ALLOWED_PORTS_FILE" ]] || return 0
    local raw port proto scope origin extra
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        [[ -z "$raw" || "$raw" == \#* ]] && continue
        raw="${raw//\\t/$'\t'}"
        IFS=$'\t' read -r port proto scope origin extra <<<"$raw"
        [[ -z "$extra" && "$port" =~ ^[0-9]+$ ]] || continue
        (( 10#$port >= 1 && 10#$port <= 65535 )) || continue
        [[ "$proto" == tcp || "$proto" == udp ]] || continue
        [[ "$scope" == host || "$scope" == docker ]] || continue
        [[ -n "$origin" ]] || continue
        printf '%s\t%s\t%s\t%s\n' "$port" "$proto" "$scope" "$origin"
    done <"$ALLOWED_PORTS_FILE"
}

save_allowed_ports() {
    local -a entries=("$@")
    {
        printf '# Gerenciado por secure-server.sh (open-port / close-port).\n'
        printf '# Formato: <porta><TAB><proto><TAB><escopo><TAB><origem>.\n'
        if (( ${#entries[@]} )); then
            printf '%s\n' "${entries[@]}"
        fi
    } | write_atomic "$ALLOWED_PORTS_FILE" 0600
}

# Constrói a linha iptables para INPUT (host) ou VPS-DOCKER-ALLOW (docker),
# no formato esperado pelos arquivos -restore.
build_rule_line() {
    local scope="$1" port="$2" proto="$3"
    case "$scope" in
        host)
            printf -- '-A INPUT -p %s -m conntrack --ctstate NEW --dport %d -j ACCEPT\n' "$proto" "$port"
            ;;
        docker)
            printf -- '-A VPS-DOCKER-ALLOW -p %s -m conntrack --ctstate NEW --ctorigdstport %d -j ACCEPT\n' "$proto" "$port"
            ;;
        *) die "Escopo invalido: ${scope} (esperado host ou docker)." ;;
    esac
}

# Elimina ocorrências runtime de uma porta em ambas as políticas e famílias.
# A reconstrução subsequente restaura apenas o que estiver no estado canônico.
delete_runtime_port() {
    local port="$1" proto="$2"
    while iptables -D INPUT -p "$proto" -m conntrack --ctstate NEW --dport "$port" -j ACCEPT 2>/dev/null; do :; done
    while ip6tables -D INPUT -p "$proto" -m conntrack --ctstate NEW --dport "$port" -j ACCEPT 2>/dev/null; do :; done
    while iptables -D VPS-DOCKER-ALLOW -p "$proto" -m conntrack --ctstate NEW --ctorigdstport "$port" -j ACCEPT 2>/dev/null; do :; done
    while ip6tables -D VPS-DOCKER-ALLOW -p "$proto" -m conntrack --ctstate NEW --ctorigdstport "$port" -j ACCEPT 2>/dev/null; do :; done
}

# Remove estados de conexão existentes cujo destino original era a porta.
# Isso cobre tanto um serviço no host quanto uma porta Docker com DNAT: para
# ambos, --orig-port-dst é a porta pública antes da tradução. O próximo pacote
# de uma sessão removida não casa com ESTABLISHED e encontra o DROP da política.
terminate_port_connections() {
    local port="$1" proto="$2" family
    if ! command -v conntrack >/dev/null 2>&1; then
        log AVISO "conntrack nao esta instalado; conexoes ja estabelecidas em ${port}/${proto} expirarao normalmente. Rode install para habilitar derrubada imediata."
        return 1
    fi
    for family in ipv4 ipv6; do
        conntrack -D -f "$family" -p "$proto" --orig-port-dst "$port" >/dev/null 2>&1 || true
    done
}

# -F INPUT apagaria o salto do Fail2Ban e os bans deixariam de valer; os saltos
# entram na mesma transacao do restore, sem janela de exposicao.
apply_host_rules() {
    local tool="$1" file="$2" jumps
    jumps="$("$tool" -S INPUT 2>/dev/null | grep -E -- '-j f2b-' || true)"
    F2B_JUMPS="$jumps" awk '{ print } $0 == "-F INPUT" && ENVIRON["F2B_JUMPS"] != "" { print ENVIRON["F2B_JUMPS"] }' "$file" \
        | "$tool"-restore --noflush
}

# Regenera deterministamente uma familia. O estado canônico é a única fonte
# das portas dinâmicas: nunca reutilizamos regras antigas do arquivo, pois isso
# faria uma porta fechada reaparecer ou duplicaria ACCEPTs a cada operação.
refresh_ruleset() {
    local family="$1" scope="$2"  # family: v4|v6; scope: host|docker
    local tool file rules=() entry port proto
    if [[ "$family" == "v4" ]]; then
        tool="iptables"; file="$HOST_V4"
        [[ "$scope" == "docker" ]] && file="$DOCKER_V4"
    else
        tool="ip6tables"; file="$HOST_V6"
        [[ "$scope" == "docker" ]] && file="$DOCKER_V6"
    fi

    while IFS=$'\t' read -r port proto entry_scope entry_origin; do
        [[ "$entry_scope" == "$scope" ]] || continue
        rules+=("$(build_rule_line "$scope" "$port" "$proto")")
    done < <(load_allowed_ports)

    local header
    if [[ "$scope" == "host" ]]; then
        header="*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-F INPUT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        header+="
# Docker/Compose/Swarm podem acessar qualquer servico no host; estas interfaces
# sao internas e nao correspondem a trafego vindo da Internet.
-A INPUT -i docker0 -j ACCEPT
-A INPUT -i br-+ -j ACCEPT
-A INPUT -i docker_gwbridge -j ACCEPT"
        if [[ "$family" == "v4" ]]; then
            header+="
-A INPUT -p icmp -j ACCEPT
-A INPUT -p udp --sport 67 --dport 68 -j ACCEPT"
        else
            header+="
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p udp --sport 547 --dport 546 -j ACCEPT"
        fi
        header+="
-A INPUT -p tcp -m conntrack --ctstate NEW -m multiport --dports 22,80,443 -j ACCEPT"
    fi

    {
        if [[ "$scope" == "host" ]]; then
            printf '%s\n' "$header"
        else
            printf '%s\n' "*filter
:VPS-DOCKER - [0:0]
:VPS-DOCKER-ALLOW - [0:0]
-F VPS-DOCKER
-F VPS-DOCKER-ALLOW
-A VPS-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A VPS-DOCKER -i docker0 -j RETURN
-A VPS-DOCKER -i br-+ -j RETURN
-A VPS-DOCKER -i docker_gwbridge -j ACCEPT
-A VPS-DOCKER -j VPS-DOCKER-ALLOW
-A VPS-DOCKER -j DROP
-A VPS-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 80 -j ACCEPT
-A VPS-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 443 -j ACCEPT"
        fi
        printf '%s\n' "$PORT_MARKER_BEGIN"
        printf '%s\n' '# Gerado a partir de secure-allowed-ports.list; nao edite este bloco.'
        printf '%s\n' "${rules[@]}"
        printf '%s\n' "$PORT_MARKER_END"
        [[ "$scope" == "docker" ]] && printf '%s\n' '-A VPS-DOCKER-ALLOW -j RETURN'
        printf '%s\n' "COMMIT"
    } > "$file.tmp"
    if [[ "$family" == "v6" ]] && ! ipv6_available; then
        install -o root -g root -m 0600 "$file.tmp" "$file"
        rm -f -- "$file.tmp"
        return 0
    fi
    "$tool"-restore --test --noflush <"$file.tmp" || die "Arquivo ${file} falhou no teste de sintaxe."
    install -o root -g root -m 0600 "$file.tmp" "$file"
    rm -f -- "$file.tmp"

    if [[ "$scope" == "host" ]]; then
        apply_host_rules "$tool" "$file"
    else
        if service_is_active docker && "$tool" -S DOCKER-USER >/dev/null 2>&1; then
            "$tool"-restore --noflush <"$file"
            ensure_docker_jump "$tool"
        fi
    fi
}

# Refresca ambas as familias de um escopo.
refresh_all() {
    local scope="$1"
    refresh_ruleset v4 "$scope"
    refresh_ruleset v6 "$scope"
}

# Adiciona uma entrada ao arquivo canônico. Retorna 0 quando a entrada era nova
# e 1 quando já existia; em ambos os casos elimina duplicatas legadas.
add_allowed_entry() {
    local scope="$1" port="$2" proto="$3" origin="$4"
    local entries=() entry entry_port entry_proto entry_scope entry_origin found=0
    while IFS=$'\t' read -r entry_port entry_proto entry_scope entry_origin; do
        if [[ "$entry_port" == "$port" && "$entry_proto" == "$proto" && "$entry_scope" == "$scope" ]]; then
            if (( found == 0 )); then
                entries+=("${port}"$'\t'"${proto}"$'\t'"${scope}"$'\t'"${origin}")
                found=1
            fi
            continue
        fi
        entries+=("${entry_port}"$'\t'"${entry_proto}"$'\t'"${entry_scope}"$'\t'"${entry_origin}")
    done < <(load_allowed_ports)
    if (( found == 0 )); then
        entries+=("${port}"$'\t'"${proto}"$'\t'"${scope}"$'\t'"${origin}")
    fi
    save_allowed_ports "${entries[@]}"
    (( found == 0 ))
}

# Remove uma porta dos dois escopos numa única escrita atômica.
remove_allowed_port() {
    local port="$1" proto="$2"
    local entries=() entry_port entry_proto entry_scope entry_origin removed=0
    while IFS=$'\t' read -r entry_port entry_proto entry_scope entry_origin; do
        if [[ "$entry_port" == "$port" && "$entry_proto" == "$proto" ]]; then
            removed=1
            continue
        fi
        entries+=("${entry_port}"$'\t'"${entry_proto}"$'\t'"${entry_scope}"$'\t'"${entry_origin}")
    done < <(load_allowed_ports)
    save_allowed_ports "${entries[@]}"
    (( removed ))
}

require_installed() {
    [[ -f "$HOST_V4" && -f "$DOCKER_V4" ]] \
        || die "Setup inicial nao encontrado. Rode primeiro: sudo ./${SCRIPT_NAME} install"
}

# Portas da politica fixa nao passam pelo estado canonico.
reject_fixed_port() {
    local port="$1" proto="$2"
    if [[ "$proto" == tcp ]]; then
        case "$port" in
            22|80|443) die "Porta ${port}/tcp faz parte da politica fixa e permanece aberta; nenhuma alteracao foi feita." ;;
        esac
    fi
}

cmd_install() {
    validate_platform
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Outra instancia de ${SCRIPT_NAME} esta em execucao."
    validate_authorized_keys
    capture_initial_state
    prepare_backup_dir
    trap 'handle_error $? $LINENO' ERR
    trap handle_signal INT TERM
    trap handle_exit EXIT

    ensure_packages
    validate_firewall_environment
    validate_public_interface
    validate_ssh_port
    backup_configuration
    MUTATIONS_STARTED=1
    configure_ssh
    configure_firewall
    configure_fail2ban
    print_report

    SUCCESS=1
    trap - EXIT ERR INT TERM
    log INFO "Configuracao concluida."
}

cmd_open_port() {
    local spec=""
    while (( $# )); do
        case "$1" in
            # Compatibilidade: open-port agora sempre cobre host e Docker.
            --force|-f) : ;;
            --help|-h) shift; show_port_help; return 0 ;;
            --) shift; break ;;
            -*) die "Opcao desconhecida para open-port: $1" ;;
            *) spec="$1" ;;
        esac
        shift
    done
    [[ -n "$spec" ]] || die "Uso: sudo ./${SCRIPT_NAME} open-port <PORTA>[/udp]"
    (( EUID == 0 )) || die "Execute como root: sudo ./${SCRIPT_NAME} open-port ..."
    require_installed

    local proto port
    parse_port_spec "$spec" proto port
    reject_fixed_port "$port" "$proto"

    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Outra instancia de ${SCRIPT_NAME} esta em execucao."

    # Backup mínimo para auditoria, antes de qualquer mutação.
    local stamp; stamp="$(date -u '+%Y%m%dT%H%M%S.%NZ')"
    local snap="${BACKUP_OPEN_BASE}-${stamp}"
    install -d -o root -g root -m 0700 "$snap"
    [[ -f "$HOST_V4" ]] && cp -a "$HOST_V4" "$snap/host.v4"
    [[ -f "$HOST_V6" ]] && cp -a "$HOST_V6" "$snap/host.v6"
    [[ -f "$DOCKER_V4" ]] && cp -a "$DOCKER_V4" "$snap/docker.v4"
    [[ -f "$DOCKER_V6" ]] && cp -a "$DOCKER_V6" "$snap/docker.v6"
    [[ -f "$ALLOWED_PORTS_FILE" ]] && cp -a "$ALLOWED_PORTS_FILE" "$snap/allowed-ports.list"

    local host_added=0 docker_added=0
    # Uma única chamada é sempre uma escolha explícita do operador, para os
    # dois caminhos. Não use "managed": parecia que Docker tinha aberto a
    # porta automaticamente, o que não é verdade.
    add_allowed_entry host "$port" "$proto" explicit && host_added=1 || true
    add_allowed_entry docker "$port" "$proto" explicit && docker_added=1 || true

    # Remove sobras de versões antigas e reconstrói ambas as políticas.
    delete_runtime_port "$port" "$proto"
    refresh_all host
    refresh_all docker

    if (( host_added || docker_added )); then
        log INFO "Porta ${port}/${proto} aberta nos escopos host e docker. Persistente no boot."
    else
        log INFO "Porta ${port}/${proto} ja estava liberada nos escopos host e docker; regras reaplicadas."
    fi
}

cmd_close_port() {
    local spec=""
    while (( $# )); do
        case "$1" in
            --force|-f) : ;;
            --help|-h) shift; show_port_help; return 0 ;;
            --) shift; break ;;
            -*) die "Opcao desconhecida para close-port: $1" ;;
            *) spec="$1" ;;
        esac
        shift
    done
    [[ -n "$spec" ]] || die "Uso: sudo ./${SCRIPT_NAME} close-port <PORTA>[/udp]"
    (( EUID == 0 )) || die "Execute como root: sudo ./${SCRIPT_NAME} close-port ..."
    require_installed

    local proto port
    parse_port_spec "$spec" proto port
    reject_fixed_port "$port" "$proto"

    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Outra instancia de ${SCRIPT_NAME} esta em execucao."

    local removed=0
    remove_allowed_port "$port" "$proto" && removed=1 || true
    # Mesmo sem registro canônico, elimina regras órfãs e reconstroi os dois
    # arquivos; close-port é corretivo e idempotente.
    delete_runtime_port "$port" "$proto"
    refresh_all host
    refresh_all docker
    local sessions_invalidated=0
    terminate_port_connections "$port" "$proto" && sessions_invalidated=1 || true

    if (( removed )); then
        if (( sessions_invalidated )); then
            log INFO "Porta ${port}/${proto} fechada nos escopos host e docker, removida da persistencia e sessoes existentes invalidadas."
        else
            log INFO "Porta ${port}/${proto} fechada nos escopos host e docker e removida da persistencia."
        fi
    else
        log INFO "Porta ${port}/${proto} nao constava no estado; host e docker foram verificados e limpos."
    fi
}

cmd_list_ports() {
    local filter="" only_docker=0 only_host=0
    while (( $# )); do
        case "$1" in
            --docker) only_docker=1 ;;
            --host) only_host=1 ;;
            --help|-h) shift; show_port_help; return 0 ;;
            --) shift; break ;;
            -*) die "Opcao desconhecida para list-ports: $1" ;;
            *) die "list-ports nao aceita argumentos: $1" ;;
        esac
        shift
    done
    require_installed
    printf 'PORTA\tPROTO\tESCOPO\tORIGEM\n'
    while IFS=$'\t' read -r port proto scope origin; do
        [[ -z "$port" ]] && continue
        if (( only_docker )) && [[ "$scope" != "docker" ]]; then continue; fi
        if (( only_host )) && [[ "$scope" != "host" ]]; then continue; fi
        printf '%s\t%s\t%s\t%s\n' "$port" "$proto" "$scope" "$origin"
    done < <(load_allowed_ports)
}

show_port_help() {
    cat <<EOF
Uso: sudo ./${SCRIPT_NAME} <comando> [args]

Comandos:
  install                       Configura o servidor (idempotente).
  open-port <PORTA>[/udp]       Abre uma porta nos escopos host e Docker.
                                A regra Docker fica pronta mesmo se nenhum
                                container publicar a porta neste momento.
  close-port <PORTA>[/udp]      Fecha uma porta nos escopos host e Docker.
  list-ports [--docker|--host]  Lista portas liberadas (canonicas).

Exemplos:
  sudo ./${SCRIPT_NAME} open-port 5400
  sudo ./${SCRIPT_NAME} open-port 53/udp
  sudo ./${SCRIPT_NAME} list-ports --docker
  sudo ./${SCRIPT_NAME} close-port 5400
EOF
}

configure_ssh() {
    log INFO "Configurando SSH para root somente por chave."
    write_atomic "$SSH_DROPIN" 0644 <<'EOF'
# Gerenciado por secure-server.sh.
Port 22
AllowUsers root
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
    sshd -t
    verify_ssh_effective
    systemctl enable --now ssh
    systemctl reload ssh
}

render_host_v4() {
    cat <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-F INPUT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Bridges locais Docker/Compose/Swarm: acesso container -> host, nunca WAN.
-A INPUT -i docker0 -j ACCEPT
-A INPUT -i br-+ -j ACCEPT
-A INPUT -i docker_gwbridge -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -p udp --sport 67 --dport 68 -j ACCEPT
-A INPUT -p tcp -m conntrack --ctstate NEW -m multiport --dports 22,80,443 -j ACCEPT
COMMIT
EOF
}

render_host_v6() {
    cat <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-F INPUT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Bridges locais Docker/Compose/Swarm: acesso container -> host, nunca WAN.
-A INPUT -i docker0 -j ACCEPT
-A INPUT -i br-+ -j ACCEPT
-A INPUT -i docker_gwbridge -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p udp --sport 547 --dport 546 -j ACCEPT
-A INPUT -p tcp -m conntrack --ctstate NEW -m multiport --dports 22,80,443 -j ACCEPT
COMMIT
EOF
}

render_docker_rules() {
    cat <<'EOF'
*filter
:VPS-DOCKER - [0:0]
:VPS-DOCKER-ALLOW - [0:0]
-F VPS-DOCKER
-F VPS-DOCKER-ALLOW
-A VPS-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A VPS-DOCKER -i docker0 -j RETURN
-A VPS-DOCKER -i br-+ -j RETURN
-A VPS-DOCKER -i docker_gwbridge -j ACCEPT
-A VPS-DOCKER -j VPS-DOCKER-ALLOW
-A VPS-DOCKER -j DROP
-A VPS-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 80 -j ACCEPT
-A VPS-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 443 -j ACCEPT
-A VPS-DOCKER-ALLOW -j RETURN
COMMIT
EOF
}

ensure_docker_jump() {
    local tool="$1"
    while "$tool" -D DOCKER-USER -j VPS-DOCKER 2>/dev/null; do :; done
    "$tool" -I DOCKER-USER 1 -j VPS-DOCKER
}

# O NetBird pode substituir o resolv.conf do host por um DNS acessível apenas
# no namespace do host. Containers usam estes resolvers públicos estáveis para
# builds e tráfego de saída, sem alterar o DNS do próprio VPS.
render_docker_daemon_config() {
    python3 - "$DOCKER_DAEMON_JSON" <<'PY'
import json
import os
import sys

path = sys.argv[1]
config = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as source:
            config = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Nao foi possivel ler {path}: {error}", file=sys.stderr)
        raise SystemExit(1)
if not isinstance(config, dict):
    print(f"{path} deve conter um objeto JSON.", file=sys.stderr)
    raise SystemExit(1)
config["dns"] = ["1.1.1.1", "8.8.8.8"]
print(json.dumps(config, indent=2, sort_keys=True))
PY
}

# Retorna 0 somente quando daemon.json mudou e o Docker ativo precisa reiniciar.
configure_docker_dns() {
    command -v docker >/dev/null 2>&1 || return 1
    command -v dockerd >/dev/null 2>&1 || die "dockerd nao foi encontrado."

    install -d -o root -g root -m 0755 "$(dirname "$DOCKER_DAEMON_JSON")"
    local rendered current=""
    rendered="$(render_docker_daemon_config)" || die "Falha ao gerar ${DOCKER_DAEMON_JSON}. Corrija o JSON antes de executar install."
    [[ -f "$DOCKER_DAEMON_JSON" ]] && current="$(<"$DOCKER_DAEMON_JSON")"
    if [[ "$current" == "$rendered" ]]; then
        return 1
    fi

    printf '%s\n' "$rendered" | write_atomic "$DOCKER_DAEMON_JSON" 0644
    dockerd --validate --config-file "$DOCKER_DAEMON_JSON" >/dev/null \
        || die "${DOCKER_DAEMON_JSON} falhou na validacao do dockerd."
    log INFO "Configurado DNS publico para containers: 1.1.1.1, 8.8.8.8."
    return 0
}

configure_firewall() {
    log INFO "Configurando firewall iptables e a chain DOCKER-USER."
    local docker_dns_changed=0
    configure_docker_dns && docker_dns_changed=1 || true
    render_host_v4 | write_atomic "$HOST_V4" 0600
    render_host_v6 | write_atomic "$HOST_V6" 0600
    render_docker_rules | write_atomic "$DOCKER_V4" 0600
    render_docker_rules | write_atomic "$DOCKER_V6" 0600

    iptables-restore --test --noflush <"$HOST_V4"
    iptables-restore --test --noflush <"$DOCKER_V4"
    if ipv6_available; then
        ip6tables-restore --test --noflush <"$HOST_V6"
        ip6tables-restore --test --noflush <"$DOCKER_V6"
    fi

    # O UFW sai do caminho: ele conflita com as regras do Docker.
    # Removemos o pacote para garantir que nenhuma ferramenta ou atualizacao
    # reative o UFW por baixo dos panos.
    if (( UFW_WAS_INSTALLED )); then
        purge_ufw || die "Falha ao remover o pacote ufw."
    else
        systemctl disable --now ufw >/dev/null 2>&1 || true
    fi
    apply_host_rules iptables "$HOST_V4"
    if ipv6_available; then
        apply_host_rules ip6tables "$HOST_V6"
    fi

    write_atomic "$HOST_UNIT" 0644 <<'UNIT'
[Unit]
Description=Secure host firewall
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/iptables-restore --noflush /etc/iptables/secure-host.v4
ExecStart=/bin/sh -ec 'if [ -e /proc/net/if_inet6 ]; then exec /usr/sbin/ip6tables-restore --noflush /etc/iptables/secure-host.v6; fi'

[Install]
WantedBy=multi-user.target
UNIT

    write_atomic "$DOCKER_DROPIN" 0644 <<'UNIT'
[Service]
# A politica entra antes do dockerd, para containers com restart automatico nao
# ficarem expostos, e de novo depois, garantindo o salto no topo de DOCKER-USER.
ExecStartPre=/bin/sh -ec 'for family in 4 6; do if [ "$$family" = 4 ]; then tool=/usr/sbin/iptables; else [ -e /proc/net/if_inet6 ] || continue; tool=/usr/sbin/ip6tables; fi; $$tool -S DOCKER-USER >/dev/null 2>&1 || $$tool -N DOCKER-USER; $${tool}-restore --noflush < /etc/iptables/secure-docker.v$$family; while $$tool -D DOCKER-USER -j VPS-DOCKER 2>/dev/null; do :; done; $$tool -I DOCKER-USER 1 -j VPS-DOCKER; done'
ExecStartPost=/bin/sh -ec 'for family in 4 6; do if [ "$$family" = 4 ]; then tool=/usr/sbin/iptables; else [ -e /proc/net/if_inet6 ] || continue; tool=/usr/sbin/ip6tables; fi; $$tool -S DOCKER-USER >/dev/null 2>&1 || $$tool -N DOCKER-USER; $${tool}-restore --noflush < /etc/iptables/secure-docker.v$$family; while $$tool -D DOCKER-USER -j VPS-DOCKER 2>/dev/null; do :; done; $$tool -I DOCKER-USER 1 -j VPS-DOCKER; done'
UNIT

    systemctl daemon-reload
    systemctl enable --now secure-host-firewall
    # install também respeita portas já registradas: o arquivo canônico é a
    # fonte de verdade, inclusive em uma reinstalação do hardening.
    refresh_all host
    refresh_all docker
    if (( docker_dns_changed )) && service_is_active docker; then
        log INFO "Reiniciando Docker para aplicar o DNS dos containers."
        DOCKER_RESTARTED=1
        systemctl restart docker
    fi
}

configure_fail2ban() {
    log INFO "Configurando Fail2Ban para SSH."
    [[ -f /etc/fail2ban/action.d/iptables-multiport.conf ]] || die "Acao iptables-multiport do Fail2Ban nao foi encontrada."
    write_atomic "$F2B_JAIL" 0644 <<'EOF'
# Gerenciado por secure-server.sh.
[sshd]
enabled = true
port = 22
protocol = tcp
backend = systemd
filter = sshd[mode=aggressive]
mode = aggressive
banaction = iptables-multiport
maxretry = 3
findtime = 10m
bantime = 1h
EOF
    rm -f -- "$F2B_LEGACY_JAIL"
    fail2ban-client -t
    systemctl enable --now fail2ban
    systemctl restart fail2ban

    # Aguarda o socket do fail2ban ficar pronto antes do 'status sshd'.
    # Em 24.04 ha uma janela de ~1-2s em que 'is-active' retorna 'active'
    # mas o socket /var/run/fail2ban/fail2ban.sock ainda nao existe.
    local f2b_attempts=0
    while (( f2b_attempts < 30 )); do
        if [[ -S /var/run/fail2ban/fail2ban.sock ]] && fail2ban-client ping >/dev/null 2>&1; then
            break
        fi
        sleep 1
        f2b_attempts=$((f2b_attempts + 1))
    done
    if (( f2b_attempts >= 30 )); then
        log AVISO "Socket do Fail2Ban nao ficou pronto apos 30s; continuando mesmo assim."
    fi
    fail2ban-client status sshd >/dev/null
}

print_report() {
    printf '\n========== RELATORIO FINAL ==========\n'
    printf '\n[iptables INPUT]\n'
    iptables -S INPUT
    printf '\n[iptables DOCKER-USER]\n'
    iptables -S DOCKER-USER 2>/dev/null || printf 'Docker ainda nao esta ativo.\n'
    printf '\n[Portas Docker permitidas]\n'
    iptables -S VPS-DOCKER-ALLOW 2>/dev/null || printf 'Docker ainda nao esta ativo.\n'
    printf '\nLiberar Docker 5400: sudo ./%s open-port 5400\n' "$SCRIPT_NAME"
    printf '\n[Fail2Ban]\n'
    fail2ban-client status sshd
    printf '\nBackup: %s\n' "$BACKUP_DIR"
    printf '=====================================\n'
}

main() {
    local sub="${1:-}"
    if [[ -z "$sub" ]]; then
        show_help
        return 0
    fi
    case "$sub" in
        install)
            cmd_install
            ;;
        open-port|allow-port)
            shift; cmd_open_port "$@"
            ;;
        close-port|disallow-port)
            shift; cmd_close_port "$@"
            ;;
        list-ports)
            shift; cmd_list_ports "$@"
            ;;
        help|--help|-h)
            show_port_help
            ;;
        *)
            die "Comando desconhecido: '${sub}'. Rode: sudo ./${SCRIPT_NAME} help"
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
