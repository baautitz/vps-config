# `secure-efa-server.sh` — hardening para VPS Ubuntu 22.04/24.04

Script de hardening "bater e esquecer" para um VPS Ubuntu que serve páginas
via Docker. Ele aplica três camadas de proteção — SSH, Fail2Ban e iptables —
e deixa o firewall pronto para coexistir com o Docker sem o UFW atrapalhar.

## Visão geral

| Camada | O que faz | Estado final |
|---|---|---|
| SSH | Força chave pública, desativa senha, libera apenas `root`. | `Port 22`, `PermitRootLogin prohibit-password`, `PasswordAuthentication no` |
| Fail2Ban | Banir 1 h após 3 falhas em 10 min. | Jail `sshd` ativo, usando `iptables-multiport` |
| iptables host | Input padrão `DROP`, abre apenas TCP 22, 80 e 443. | Chains `INPUT`/`FORWARD`/`OUTPUT` em `/etc/iptables/secure-efa-host.v{4,6}` |
| iptables Docker | `DOCKER-USER` salta para `EFA-DOCKER`, que libera só 80 e 443 por padrão. | Chains `EFA-DOCKER`/`EFA-DOCKER-ALLOW` em `/etc/iptables/secure-efa-docker.v{4,6}` |
| UFW | Removido por padrão. | O pacote `ufw` é purgado (não apenas desativado) |

Docker continua dono de `NAT`, `DOCKER`, `DOCKER-BRIDGE`, etc. O script só
interfere na chain `DOCKER-USER` — ponto oficialmente documentado para
políticas do host em cima do Docker.

## Pré-requisitos

- Ubuntu 22.04 ou 24.04 com `systemd`.
- Executar como `root` (`sudo ./secure-efa-server.sh`).
- `/root/.ssh/authorized_keys` válido, com permissões seguras
  (`700` em `/root` e `/root/.ssh`, `600` em `authorized_keys`).
- Nenhum dos seguintes em uso: `firewalld`, `nftables.service`,
  Docker com `"iptables": false` ou backend `"nftables"`.
- Conexão com a internet para `apt-get install` (caso `openssh-server`,
  `fail2ban`, `python3-systemd` ou `iptables` ainda não estejam instalados).

> O script aborta com mensagem clara se algum desses pré-requisitos falhar.

## Como rodar

````bash
sudo ./secure-efa-server.sh
# ou, para ver ajuda:
sudo ./secure-efa-server.sh --help
````

A execução é idempotente: pode rodar de novo e o resultado será equivalente
(regras regravadas, serviços apenas recarregados, backup novo criado).

## O que o script faz, passo a passo

1. **Valida o ambiente** — root, Ubuntu LTS correto, `systemd` ativo,
   `/root/.ssh/authorized_keys` válido, permissões seguras, ausência de
   `firewalld`/`nftables`/Docker em modo incompatível.
2. **Trava a execução** com `flock` em `/run/lock/secure-efa-server.lock`.
3. **Captura o estado inicial** — status de `ssh`, `fail2ban`, `ufw` e a
   presença do pacote `ufw`. Tudo é gravado em `/var/backups/secure-efa-server/<timestamp>/initial-state`.
4. **Faz backup** dos arquivos que serão modificados
   (`/etc/ssh/sshd_config`, drop-ins, jails, regras `iptables-save`, etc.).
5. **Garante pacotes**: `openssh-server`, `fail2ban`, `python3-systemd`, `iptables`.
6. **Configura SSH** via drop-in `/etc/ssh/sshd_config.d/00-secure-efa-server.conf`
   e recarrega o serviço.
7. **Configura o firewall**:
   - Grava `/etc/iptables/secure-efa-host.v4` e `.v6`.
   - Grava `/etc/iptables/secure-efa-docker.v4` e `.v6`.
   - Testa cada arquivo com `iptables-restore --test --noflush`.
   - **Purga o pacote `ufw`** se ele estava instalado, garantindo que
     nenhuma ferramenta futura reative um firewall conflitante.
   - Cria o serviço `secure-efa-host-firewall.service` (carrega `host.v4`/`.v6`
     no boot, antes do `docker.service`).
   - Cria o drop-in `/etc/systemd/system/docker.service.d/10-secure-efa-firewall.conf`
     que reaplica as chains `EFA-DOCKER`/`EFA-DOCKER-ALLOW` e o salto
     `DOCKER-USER → EFA-DOCKER` toda vez que o Docker inicia.
   - Aplica as regras imediatamente se o Docker já estiver ativo.
8. **Configura Fail2Ban** — escreve `/etc/fail2ban/jail.local`, remove o
   legacy `/etc/fail2ban/jail.d/sshd.local`, valida com `fail2ban-client -t`,
   reinicia o serviço e confere que a jail `sshd` subiu.
9. **Imprime relatório final** com `iptables -S`, status do Fail2Ban e
   localização do backup.

## Estrutura de arquivos criados

````
/etc/ssh/sshd_config.d/00-secure-efa-server.conf
/etc/fail2ban/jail.local
/etc/iptables/secure-efa-host.v4
/etc/iptables/secure-efa-host.v6
/etc/iptables/secure-efa-docker.v4
/etc/iptables/secure-efa-docker.v6
/etc/systemd/system/secure-efa-host-firewall.service
/etc/systemd/system/docker.service.d/10-secure-efa-firewall.conf
/var/backups/secure-efa-server/<UTC-timestamp>/
├── initial-state
├── iptables.v4
├── iptables.v6
└── items/<cada arquivo sobrescrito>
````

## Reversão (rollback)

O script trata dois sinais de erro: falha de qualquer comando (`ERR`)
e interrupção do usuário (`INT`/`TERM`). Em ambos:

- Para o `fail2ban`.
- Restaura `iptables-save`/`ip6tables-save` capturado no backup.
- Recoloca cada arquivo no estado original (ou remove, se não existia antes).
- Reaplica o estado `active`/`enabled` original de `ssh`, `fail2ban` e `ufw`.
- Se o `ufw` estava instalado no estado inicial, tenta reinstalar o pacote
  antes de reativá-lo.

Se algo der errado durante a reversão, o backup fica em
`/var/backups/secure-efa-server/<timestamp>/` para inspeção manual.

## Modelo de chains iptables

### Host (entrada do próprio servidor)

````
*filter
:INPUT DROP
:FORWARD DROP
:OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT                            # IPv4
-A INPUT -p udp --sport 67 --dport 68 -j ACCEPT       # DHCP client
-A INPUT -p tcp -m conntrack --ctstate NEW -m multiport --dports 22,80,443 -j ACCEPT
COMMIT
````

A versão IPv6 substitui `icmp` por `ipv6-icmp` e libera o range de
DHCPv6 (`sport 547 --dport 546`). Trafego IPv6 forwarding é descartado
no `FORWARD`.

### Docker (chain `DOCKER-USER` → `EFA-DOCKER`)

Docker só consulta a chain `DOCKER-USER` quando o pacote chega da WAN
(antes do DNAT). O script instala:

````
-A DOCKER-USER -j EFA-DOCKER          # injetado pelo drop-in do docker.service
-A EFA-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A EFA-DOCKER -i docker0 -j RETURN    # trafego interno docker0
-A EFA-DOCKER -i br+ -j RETURN        # trafego interno em bridges user-defined
-A EFA-DOCKER -j EFA-DOCKER-ALLOW
-A EFA-DOCKER -j DROP
-A EFA-DOCKER-ALLOW -p tcp --ctorigdstport 80 -j ACCEPT
-A EFA-DOCKER-ALLOW -p tcp --ctorigdstport 443 -j ACCEPT
-A EFA-DOCKER-ALLOW -j RETURN
````

Pontos-chave:

- Apenas a porta de destino **publicada** no host (`--ctorigdstport`) é
  avaliada — é assim que Docker distingue "pacote chegou na porta 5400"
  vs "pacote chegou na 80".
- Conexões estabelecidas/relacionadas passam direto.
- Pacotes vindos de uma bridge do Docker (`br+`) voltam antes do
  bloqueio, evitando loop com regras do próprio Docker.

## Pontos a monitorar

- **Cloud-init / unattended-upgrades** podem reinstalar `ufw` em
  algumas imagens Ubuntu. Se isso acontecer, rode o script de novo —
  ele vai detectar e purgar de novo.
- **Drop-in do Docker**: editar
  `/etc/systemd/system/docker.service.d/10-secure-efa-firewall.conf`
  é seguro, mas lembre que o script regrava esse arquivo a cada
  execução. Coloque mudanças persistentes em uma camada superior.
- **`/etc/docker/daemon.json`**: nunca defina `"iptables": false` ou
  `"firewall-backend": "nftables"` — o script aborta imediatamente.