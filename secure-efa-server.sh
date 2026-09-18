#!/usr/bin/env bash

# Hardening simples para Ubuntu 22.04/24.04 com SSH, Fail2Ban e iptables.
# Docker continua dono do NAT/publicacao; este script usa DOCKER-USER.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_NAME="${0##*/}"
readonly BACKUP_BASE="/var/backups/secure-efa-server"
readonly LOCK_FILE="/run/lock/secure-efa-server.lock"
readonly AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
readonly SSH_DROPIN="/etc/ssh/sshd_config.d/00-secure-efa-server.conf"
readonly F2B_JAIL="/etc/fail2ban/jail.local"
readonly F2B_LEGACY_JAIL="/etc/fail2ban/jail.d/sshd.local"
readonly IPTABLES_DIR="/etc/iptables"
readonly HOST_V4="${IPTABLES_DIR}/secure-efa-host.v4"
readonly HOST_V6="${IPTABLES_DIR}/secure-efa-host.v6"
readonly DOCKER_V4="${IPTABLES_DIR}/secure-efa-docker.v4"
readonly DOCKER_V6="${IPTABLES_DIR}/secure-efa-docker.v6"
readonly HOST_UNIT="/etc/systemd/system/secure-efa-host-firewall.service"
readonly DOCKER_DROPIN="/etc/systemd/system/docker.service.d/10-secure-efa-firewall.conf"
readonly PORT_MARKER_BEGIN="# BEGIN secure-efa-server managed ports"
readonly PORT_MARKER_END="# END secure-efa-server managed ports"
readonly ALLOWED_PORTS_FILE="${IPTABLES_DIR}/secure-efa-allowed-ports.list"
readonly BACKUP_OPEN_BASE="/var/backups/secure-efa-server/open-port"

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
  open-port <PORTA>[/udp]       Abre uma porta (Docker ou host) e persiste no boot.
  close-port <PORTA>[/udp]      Fecha uma porta e remove da persistencia.
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
        22.04|24.04) ;;
        *) die "Versao nao suportada: use Ubuntu 22.04 ou 24.04." ;;
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
}

package_is_installed() {
    dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -qx installed
}

purge_ufw() {
    log INFO "Removendo o pacote ufw (iptables e a fonte unica de verdade)."
    systemctl disable --now ufw >/dev/null 2>&1 || true
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y -o Dpkg::Options::=--force-confold ufw || return 1
    apt-get autoremove --purge -y >/dev/null 2>&1 || true
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
    for package in openssh-server fail2ban python3-systemd iptables; do
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
    command -v iptables >/dev/null || die "iptables nao foi encontrado."
    command -v iptables-restore >/dev/null || die "iptables-restore nao foi encontrado."
    command -v ip6tables >/dev/null || die "ip6tables nao foi encontrado."
    command -v ip6tables-restore >/dev/null || die "ip6tables-restore nao foi encontrado."

    if service_is_active firewalld || service_is_enabled firewalld || service_is_active nftables || service_is_enabled nftables; then
        die "firewalld ou nftables.service ja controla o firewall."
    fi

    if [[ -f /etc/docker/daemon.json ]]; then
        grep -Eq '"iptables"[[:space:]]*:[[:space:]]*false' /etc/docker/daemon.json && die "Docker foi configurado com iptables=false."
        grep -Eq '"firewall-backend"[[:space:]]*:[[:space:]]*"nftables"' /etc/docker/daemon.json && die "Docker usa backend nftables; este script exige o backend iptables."
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
    backup_item "$HOST_UNIT" host-unit
    backup_item "$DOCKER_DROPIN" docker-dropin
    iptables-save >"${BACKUP_DIR}/iptables.v4"
    ip6tables-save >"${BACKUP_DIR}/iptables.v6"
    chmod 0600 "${BACKUP_DIR}/iptables.v4" "${BACKUP_DIR}/iptables.v6"
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
    ip6tables-restore <"${BACKUP_DIR}/iptables.v6" || failed=1
    restore_item /etc/ssh/sshd_config sshd-config || failed=1
    restore_item "$SSH_DROPIN" ssh-dropin || failed=1
    restore_item "$F2B_JAIL" fail2ban-jail || failed=1
    restore_item "$F2B_LEGACY_JAIL" fail2ban-legacy-jail || failed=1
    restore_item "$HOST_V4" host-v4 || failed=1
    restore_item "$HOST_V6" host-v6 || failed=1
    restore_item "$DOCKER_V4" docker-v4 || failed=1
    restore_item "$DOCKER_V6" docker-v6 || failed=1
    restore_item "$HOST_UNIT" host-unit || failed=1
    restore_item "$DOCKER_DROPIN" docker-dropin || failed=1
    systemctl daemon-reload >/dev/null 2>&1 || true

    if (( SSH_WAS_ACTIVE )); then
        sshd -t && systemctl restart ssh >/dev/null 2>&1 || failed=1
    else
        systemctl stop ssh >/dev/null 2>&1 || true
    fi
    restore_enabled_state ssh "$SSH_WAS_ENABLED"

    if (( UFW_WAS_INSTALLED )); then
        reinstall_ufw >/dev/null 2>&1 || failed=1
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
    trap - ERR INT TERM
    log ERRO "Comando falhou na linha ${line} (codigo ${status})."
    if (( MUTATIONS_STARTED && SUCCESS == 0 )); then
        rollback
    fi
    exit "$status"
}

handle_signal() {
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
    if ! [[ "$port_part" =~ ^[0-9]+$ ]] || (( port_part < 1 || port_part > 65535 )); then
        die "Porta invalida: '${spec}' (esperado 1-65535 ou 1-65535/tcp|udp)."
    fi
    case "$proto_part" in
        tcp|udp) ;;
        *) die "Protocolo invalido em '${spec}': use tcp ou udp." ;;
    esac
    printf -v "$__proto_var" '%s' "$proto_part"
    printf -v "$__port_var" '%d' "$port_part"
}

# Verifica se a porta esta publicada por algum container Docker ativo.
# Imprime no stdout uma linha por container: "<container_id>\t<porta>\t<proto>".
docker_published_ports() {
    command -v docker >/dev/null 2>&1 || return 0
    service_is_active docker || return 0
    docker ps --no-trunc --format '{{.ID}}|{{.Names}}|{{.Ports}}' 2>/dev/null \
        | awk -F'|' '
            function flush() {
                if (id != "") print id "\t" exposed_port "\t" exposed_proto
            }
            NF < 3 { next }
            {
                id = $1
                ports = $3
                np = split(ports, parts, ",")
                ep = ""
                eproto = ""
                for (i = 1; i <= np; i++) {
                    p = parts[i]
                    sub(/^ */, "", p); sub(/ *$/, "", p)
                    if (p == "") continue
                    # Ex.: "0.0.0.0:5400->80/tcp" ou "5400-5401->80-81/tcp"
                    if (match(p, /:([0-9]+)([-][0-9]+)?->[0-9]+/)) {
                        exposed_port = substr(p, RSTART+1, RLENGTH-1)
                        sub(/->.*/, "", exposed_port)
                        if (match(p, /(tcp|udp)$/)) exposed_proto = substr(p, RSTART, RLENGTH)
                        else exposed_proto = "tcp"
                        if (exposed_port ~ /^[0-9]+$/) print id "\t" exposed_port + 0 "\t" exposed_proto
                        if (match(p, /->([0-9]+)/)) {
                            ep = substr(p, RSTART+2, RLENGTH-2)
                            eproto = exposed_proto
                        }
                    } else if (match(p, /^([0-9]+)\/([a-z]+)/)) {
                        ep = substr(p, 3, RLENGTH-3); eproto = substr(p, RSTART, RLENGTH)
                        print id "\t" ep + 0 "\t" eproto
                    }
                }
            }'
}

# Resolve se a porta e Docker ou host. Imprime "docker" ou "host" no stdout.
resolve_scope() {
    local port="$1" proto="$2"
    local line container_id exposed_port exposed_proto
    while IFS=$'\t' read -r container_id exposed_port exposed_proto; do
        [[ -z "$container_id" ]] && continue
        if (( exposed_port == port )) && [[ "$exposed_proto" == "$proto" ]]; then
            printf "docker\t%s\n" "$container_id"
            return 0
        fi
    done < <(docker_published_ports)
    printf "host\n"
    return 0
}

# Remove um bloco gerenciado por marcadores de um arquivo iptables-*.v4/.v6,
# devolvendo as linhas ao stdout. Se nao houver bloco, devolve o arquivo
# inalterado. Marcadores sao comentarios no formato "# BEGIN ..." / "# END ...".
strip_managed_block() {
    local path="$1"
    [[ -f "$path" ]] || { return 0; }
    awk -v begin="$PORT_MARKER_BEGIN" -v end="$PORT_MARKER_END" '
        $0 == begin { in_block = 1; next }
        in_block && $0 == end { in_block = 0; next }
        !in_block { print }
    ' "$path"
}

# Le o conjunto gerenciado de um arquivo. Imprime "<porta>\t<proto>" por linha.
read_managed_ports() {
    local path="$1"
    [[ -f "$path" ]] || return 0
    awk -v begin="$PORT_MARKER_BEGIN" -v end="$PORT_MARKER_END" '
        $0 == begin { in_block = 1; next }
        in_block && $0 == end { in_block = 0; next }
        in_block { print }
    ' "$path"
}

# Insere as linhas geradas entre os marcadores (ou cria o bloco se nao existir)
# preservando o conteudo pre-existente do arquivo.
write_managed_block() {
    local path="$1" mode="$2" header="$3"; shift 3
    local body=("$@")
    local new_content
    new_content="$(strip_managed_block "$path")"
    {
        printf '%s\n' "$new_content"
        printf '%s\n' "$PORT_MARKER_BEGIN"
        printf '%s\n' "$header"
        printf '%s\n' "${body[@]}"
        printf '%s\n' "$PORT_MARKER_END"
    } | write_atomic "$path" "$mode"
}

# Carrega do arquivo de auditoria o conjunto canonico de portas liberadas,
# usado para sincronizar marcadores e chains ativos. Formato: "<porta>\t<proto>\n".
load_allowed_ports() {
    [[ -f "$ALLOWED_PORTS_FILE" ]] || return 0
    grep -v '^[[:space:]]*$' "$ALLOWED_PORTS_FILE" || true
}

save_allowed_ports() {
    local -a entries=("$@")
    {
        printf '# Gerenciado por secure-efa-server.sh (open-port / close-port).\n'
        printf '# Formato: <porta>\\t<proto>\\t<escopo>\\t<origem>\n'
        if (( ${#entries[@]} )); then
            printf '%s\n' "${entries[@]}"
        fi
    } | write_atomic "$ALLOWED_PORTS_FILE" 0600
}

# Constrói a linha iptables para INPUT (host) ou EFA-DOCKER-ALLOW (docker),
# no formato esperado pelos arquivos -restore.
build_rule_line() {
    local scope="$1" port="$2" proto="$3"
    case "$scope" in
        host)
            printf -- '-A INPUT -p %s -m conntrack --ctstate NEW --dport %d -j ACCEPT\n' "$proto" "$port"
            ;;
        docker)
            printf -- '-A EFA-DOCKER-ALLOW -p %s -m conntrack --ctstate NEW --ctorigdstport %d -j ACCEPT\n' "$proto" "$port"
            ;;
        *) die "Escopo invalido: ${scope} (esperado host ou docker)." ;;
    esac
}

# Aplica imediatamente uma regra em runtime (iptables/ip6tables).
apply_rule_runtime() {
    local tool="$1" scope="$2" port="$3" proto="$4" action="$5"  # action=insert|delete
    local chain rule_flag selector_flag
    case "$scope" in
        host) chain="INPUT"; selector_flag="--dport" ;;
        docker) chain="EFA-DOCKER-ALLOW"; selector_flag="--ctorigdstport" ;;
    esac
    case "$action" in
        insert) rule_flag="-I" ;;
        delete) rule_flag="-D" ;;
    esac
    "$tool" "$rule_flag" "$chain" 1 \
        -p "$proto" -m conntrack --ctstate NEW "$selector_flag" "$port" -j ACCEPT \
        >/dev/null 2>&1 || true
}

# Regenera e reaplica o conjunto completo de portas gerenciadas em uma familia
# (v4 ou v6). Reconstroi o arquivo base + reaplica no kernel.
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

    # Cabecalho + regras pre-existentes (origin=builtin) + bloco gerenciado.
    local header existing=() built=() line
    if [[ "$scope" == "host" ]]; then
        header="*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-F INPUT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
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
        # Pre-existentes (80/443) para Docker ficam em build_rule_line.
    fi

    # Coleta regras pre-existentes (builtin) do arquivo atual.
    local builtin=()
    if [[ -f "$file" ]]; then
        while IFS= read -r line; do builtin+=("$line"); done < <(read_managed_ports "$file")
        while IFS= read -r line; do
            builtin+=("$line")
        done < <(awk -v begin="$PORT_MARKER_BEGIN" '
            $0 == begin { in_block = 1; next }
            in_block { next }
            /^-A / { print }
        ' "$file")
    fi

    # Conjunto final = builtin (ja existentes antes do utilitario) + rules.
    local combined=()
    combined+=("${builtin[@]}")
    combined+=("${rules[@]}")
    combined+=("-A EFA-DOCKER-ALLOW -j RETURN")

    {
        if [[ "$scope" == "host" ]]; then
            printf '%s\n' "$header"
        else
            printf '%s\n' "*filter
:EFA-DOCKER - [0:0]
:EFA-DOCKER-ALLOW - [0:0]
-F EFA-DOCKER
-F EFA-DOCKER-ALLOW
-A EFA-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A EFA-DOCKER -i docker0 -j RETURN
-A EFA-DOCKER -i br+ -j RETURN
-A EFA-DOCKER -j EFA-DOCKER-ALLOW
-A EFA-DOCKER -j DROP"
        fi
        printf '%s\n' "${combined[@]}"
        printf '%s\n' "COMMIT"
    } > "$file.tmp"
    install -o root -g root -m 0600 "$file.tmp" "$file"
    rm -f -- "$file.tmp"

    "$tool"-restore --test --noflush <"$file" || die "Arquivo ${file} falhou no teste de sintaxe."

    if [[ "$scope" == "host" ]]; then
        systemctl reload secure-efa-host-firewall 2>/dev/null || true
        "$tool"-restore --noflush <"$file"
    else
        if service_is_active docker && "$tool" -S DOCKER-USER >/dev/null 2>&1; then
            "$tool"-restore --noflush <"$file"
            ensure_docker_jump "$tool"
        fi
    fi
}

# Refresca ambas as familias (v4 e v6) e ambos os escopos (host e docker).
refresh_all() {
    local scope="$1"
    refresh_ruleset v4 "$scope"
    refresh_ruleset v6 "$scope"
}

# Adiciona (scope,port,proto) ao arquivo canonico, idempotente.
add_allowed_entry() {
    local scope="$1" port="$2" proto="$3" origin="$4"
    local line="${port}\t${proto}\t${scope}\t${origin}"
    local current
    current="$(load_allowed_ports | grep -Fx -- "${port}	${proto}	${scope}" || true)"
    if [[ -n "$current" ]]; then
        return 1  # ja existe
    fi
    local entries=()
    while IFS= read -r e; do
        [[ -n "$e" && "$e" != "${port}	${proto}	"* ]] && entries+=("$e")
    done < <(load_allowed_ports)
    entries+=("$line")
    save_allowed_ports "${entries[@]}"
}

remove_allowed_entry() {
    local scope="$1" port="$2" proto="$3"
    local entries=() e
    while IFS= read -r e; do
        [[ -n "$e" && "$e" != "${port}	${proto}	${scope}" ]] && entries+=("$e")
    done < <(load_allowed_ports)
    save_allowed_ports "${entries[@]}"
}

require_installed() {
    [[ -f "$HOST_V4" && -f "$DOCKER_V4" ]] \
        || die "Setup inicial nao encontrado. Rode primeiro: sudo ./${SCRIPT_NAME} install"
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

    ensure_packages
    validate_firewall_environment
    backup_configuration
    MUTATIONS_STARTED=1
    configure_ssh
    configure_firewall
    configure_fail2ban
    print_report

    SUCCESS=1
    trap - ERR INT TERM
    log INFO "Configuracao concluida."
}

cmd_open_port() {
    local spec="" force=0
    while (( $# )); do
        case "$1" in
            --force|-f) force=1 ;;
            --help|-h) shift; show_port_help; return 0 ;;
            --) shift; break ;;
            -*) die "Opcao desconhecida para open-port: $1" ;;
            *) spec="$1" ;;
        esac
        shift
    done
    [[ -n "$spec" ]] || die "Uso: sudo ./${SCRIPT_NAME} open-port <PORTA>[/udp] [--force]"
    (( EUID == 0 )) || die "Execute como root: sudo ./${SCRIPT_NAME} open-port ..."
    require_installed

    local proto port
    parse_port_spec "$spec" proto port

    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Outra instancia de ${SCRIPT_NAME} esta em execucao."

    local resolved scope="" container_id=""
    resolved="$(resolve_scope "$port" "$proto")"
    scope="${resolved%%	*}"
    container_id="${resolved#*	}"
    [[ "$container_id" == "$resolved" ]] && container_id=""
    if [[ "$scope" == "host" ]] && (( force == 0 )) && command -v docker >/dev/null 2>&1 && service_is_active docker; then
        # Aviso: nenhum container publicando esta porta. Pode ser intencional.
        log AVISO "Nenhum container Docker publica ${port}/${proto}; abrindo como porta de host."
    fi

    local origin="docker:${container_id:0:12}"
    [[ "$scope" == "host" ]] && origin="manual"
    if add_allowed_entry "$scope" "$port" "$proto" "$origin"; then
        log INFO "Porta ${port}/${proto} ja estava liberada (escopo=${scope}); nada a fazer."
        return 0
    fi

    # Backup minimo para auditoria (apenas arquivos tocados).
    local stamp; stamp="$(date -u '+%Y%m%dT%H%M%S.%NZ')"
    local snap="${BACKUP_OPEN_BASE}-${stamp}"
    install -d -o root -g root -m 0700 "$snap"
    [[ -f "$HOST_V4" ]] && cp -a "$HOST_V4" "$snap/host.v4"
    [[ -f "$HOST_V6" ]] && cp -a "$HOST_V6" "$snap/host.v6"
    [[ -f "$DOCKER_V4" ]] && cp -a "$DOCKER_V4" "$snap/docker.v4"
    [[ -f "$DOCKER_V6" ]] && cp -a "$DOCKER_V6" "$snap/docker.v6"

    # Regras builtin + gerenciadas (limpa runtime antes para evitar duplicatas).
    case "$scope" in
        host)
            while iptables -D INPUT -p "$proto" -m conntrack --ctstate NEW --dport "$port" -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D INPUT -p "$proto" -m conntrack --ctstate NEW --dport "$port" -j ACCEPT 2>/dev/null; do :; done
            refresh_ruleset v4 host
            refresh_ruleset v6 host
            ;;
        docker)
            while iptables -D EFA-DOCKER-ALLOW -p "$proto" -m conntrack --ctstate NEW --ctorigdstport "$port" -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D EFA-DOCKER-ALLOW -p "$proto" -m conntrack --ctstate NEW --ctorigdstport "$port" -j ACCEPT 2>/dev/null; do :; done
            refresh_ruleset v4 docker
            refresh_ruleset v6 docker
            ;;
    esac
    log INFO "Porta ${port}/${proto} aberta (escopo=${scope}, origem=${origin}). Persistente no boot."
}

cmd_close_port() {
    local spec="" force=0
    while (( $# )); do
        case "$1" in
            --force|-f) force=1 ;;
            --help|-h) shift; show_port_help; return 0 ;;
            --) shift; break ;;
            -*) die "Opcao desconhecida para close-port: $1" ;;
            *) spec="$1" ;;
        esac
        shift
    done
    [[ -n "$spec" ]] || die "Uso: sudo ./${SCRIPT_NAME} close-port <PORTA>[/udp] [--force]"
    (( EUID == 0 )) || die "Execute como root: sudo ./${SCRIPT_NAME} close-port ..."
    require_installed

    local proto port
    parse_port_spec "$spec" proto port

    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Outra instancia de ${SCRIPT_NAME} esta em execucao."

    local removed=0
    local entry_scope
    while IFS=$'\t' read -r _p _proto entry_scope _origin; do
        [[ "$_p" == "$port" && "$_proto" == "$proto" ]] || continue
        remove_allowed_entry "$entry_scope" "$port" "$proto"
        case "$entry_scope" in
            host)
                while iptables -D INPUT -p "$proto" -m conntrack --ctstate NEW --dport "$port" -j ACCEPT 2>/dev/null; do :; done
                while ip6tables -D INPUT -p "$proto" -m conntrack --ctstate NEW --dport "$port" -j ACCEPT 2>/dev/null; do :; done
                refresh_ruleset v4 host
                refresh_ruleset v6 host
                ;;
            docker)
                while iptables -D EFA-DOCKER-ALLOW -p "$proto" -m conntrack --ctstate NEW --ctorigdstport "$port" -j ACCEPT 2>/dev/null; do :; done
                while ip6tables -D EFA-DOCKER-ALLOW -p "$proto" -m conntrack --ctstate NEW --ctorigdstport "$port" -j ACCEPT 2>/dev/null; do :; done
                refresh_ruleset v4 docker
                refresh_ruleset v6 docker
                ;;
        esac
        removed=1
    done < <(load_allowed_ports)

    if (( removed )); then
        log INFO "Porta ${port}/${proto} fechada e removida da persistencia."
    else
        log INFO "Porta ${port}/${proto} nao estava liberada; nada a fazer."
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
  open-port <PORTA>[/udp]       Abre uma porta (Docker ou host) e persiste no boot.
                                Detecta automaticamente se a porta esta publicada
                                por um container Docker.
                                Use --force para ignorar o aviso quando quiser abrir
                                como porta de host mesmo existindo Docker.
  close-port <PORTA>[/udp]      Fecha uma porta e remove da persistencia.
  list-ports [--docker|--host]  Lista portas liberadas (canonicas).

Exemplos:
  sudo ./${SCRIPT_NAME} open-port 5400
  sudo ./${SCRIPT_NAME} open-port 53/udp
  sudo ./${SCRIPT_NAME} open-port 9000 --force
  sudo ./${SCRIPT_NAME} list-ports --docker
  sudo ./${SCRIPT_NAME} close-port 5400
EOF
}

configure_ssh() {
    log INFO "Configurando SSH para root somente por chave."
    write_atomic "$SSH_DROPIN" 0644 <<'EOF'
# Gerenciado por secure-efa-server.sh.
Port 22
AllowUsers root
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
    sshd -t
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
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p udp --sport 547 --dport 546 -j ACCEPT
-A INPUT -p tcp -m conntrack --ctstate NEW -m multiport --dports 22,80,443 -j ACCEPT
COMMIT
EOF
}

render_docker_rules() {
    cat <<'EOF'
*filter
:EFA-DOCKER - [0:0]
:EFA-DOCKER-ALLOW - [0:0]
-F EFA-DOCKER
-F EFA-DOCKER-ALLOW
-A EFA-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A EFA-DOCKER -i docker0 -j RETURN
-A EFA-DOCKER -i br+ -j RETURN
-A EFA-DOCKER -j EFA-DOCKER-ALLOW
-A EFA-DOCKER -j DROP
-A EFA-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 80 -j ACCEPT
-A EFA-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 443 -j ACCEPT
-A EFA-DOCKER-ALLOW -j RETURN
COMMIT
EOF
}

ensure_docker_jump() {
    local tool="$1"
    while "$tool" -D DOCKER-USER -j EFA-DOCKER 2>/dev/null; do :; done
    "$tool" -I DOCKER-USER 1 -j EFA-DOCKER
}

apply_docker_rules_now() {
    if service_is_active docker; then
        iptables -S DOCKER-USER >/dev/null 2>&1 || die "Docker ativo sem a chain DOCKER-USER."
        iptables-restore --noflush <"$DOCKER_V4"
        ensure_docker_jump iptables
        if ip6tables -S DOCKER-USER >/dev/null 2>&1; then
            ip6tables-restore --noflush <"$DOCKER_V6"
            ensure_docker_jump ip6tables
        fi
    fi
}

configure_firewall() {
    log INFO "Configurando firewall iptables e a chain DOCKER-USER."
    render_host_v4 | write_atomic "$HOST_V4" 0600
    render_host_v6 | write_atomic "$HOST_V6" 0600
    render_docker_rules | write_atomic "$DOCKER_V4" 0600
    render_docker_rules | write_atomic "$DOCKER_V6" 0600

    iptables-restore --test --noflush <"$HOST_V4"
    ip6tables-restore --test --noflush <"$HOST_V6"
    iptables-restore --test --noflush <"$DOCKER_V4"
    ip6tables-restore --test --noflush <"$DOCKER_V6"

    # O UFW sai do caminho: ele conflita com as regras do Docker.
    # Removemos o pacote para garantir que nenhuma ferramenta ou atualizacao
    # reative o UFW por baixo dos panos.
    if (( UFW_WAS_INSTALLED )); then
        purge_ufw || die "Falha ao remover o pacote ufw."
    else
        systemctl disable --now ufw >/dev/null 2>&1 || true
    fi
    iptables-restore --noflush <"$HOST_V4"
    ip6tables-restore --noflush <"$HOST_V6"

    write_atomic "$HOST_UNIT" 0644 <<'UNIT'
[Unit]
Description=Secure EFA host firewall
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/iptables-restore --noflush /etc/iptables/secure-efa-host.v4
ExecStart=/usr/sbin/ip6tables-restore --noflush /etc/iptables/secure-efa-host.v6

[Install]
WantedBy=multi-user.target
UNIT

    write_atomic "$DOCKER_DROPIN" 0644 <<'UNIT'
[Service]
# Docker cria DOCKER-USER; esta configuracao conecta a politica do servidor.
ExecStartPost=/bin/sh -ec '/usr/sbin/iptables -S EFA-DOCKER >/dev/null 2>&1 || /usr/sbin/iptables-restore --noflush < /etc/iptables/secure-efa-docker.v4; while /usr/sbin/iptables -D DOCKER-USER -j EFA-DOCKER 2>/dev/null; do :; done; /usr/sbin/iptables -I DOCKER-USER 1 -j EFA-DOCKER; if /usr/sbin/ip6tables -S DOCKER-USER >/dev/null 2>&1; then /usr/sbin/ip6tables -S EFA-DOCKER >/dev/null 2>&1 || /usr/sbin/ip6tables-restore --noflush < /etc/iptables/secure-efa-docker.v6; while /usr/sbin/ip6tables -D DOCKER-USER -j EFA-DOCKER 2>/dev/null; do :; done; /usr/sbin/ip6tables -I DOCKER-USER 1 -j EFA-DOCKER; fi'
UNIT

    systemctl daemon-reload
    systemctl enable --now secure-efa-host-firewall
    apply_docker_rules_now
}

configure_fail2ban() {
    log INFO "Configurando Fail2Ban para SSH."
    [[ -f /etc/fail2ban/action.d/iptables-multiport.conf ]] || die "Acao iptables-multiport do Fail2Ban nao foi encontrada."
    write_atomic "$F2B_JAIL" 0644 <<'EOF'
# Gerenciado por secure-efa-server.sh.
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
    fail2ban-client status sshd >/dev/null
}

print_report() {
    printf '\n========== RELATORIO FINAL ==========\n'
    printf '\n[iptables INPUT]\n'
    iptables -S INPUT
    printf '\n[iptables DOCKER-USER]\n'
    iptables -S DOCKER-USER 2>/dev/null || printf 'Docker ainda nao esta ativo.\n'
    printf '\n[Portas Docker permitidas]\n'
    iptables -S EFA-DOCKER-ALLOW 2>/dev/null || printf 'Docker ainda nao esta ativo.\n'
    printf '\nLiberar Docker 5400: sudo iptables -I EFA-DOCKER-ALLOW 1 -p tcp -m conntrack --ctstate NEW --ctorigdstport 5400 -j ACCEPT\n'
    printf '\n[Fail2Ban]\n'
    fail2ban-client status sshd
    printf '\nBackup: %s\n' "$BACKUP_DIR"
    printf '=====================================\n'
}

main() {
    local sub="${1:-}"
    if [[ -z "$sub" ]]; then
        sub="install"
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
