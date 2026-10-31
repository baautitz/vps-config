# `secure-server.sh` — hardening para VPS Ubuntu 22.04/24.04/26.04

Script de hardening "bater e esquecer" para um VPS Ubuntu que serve páginas
via Docker. Ele aplica três camadas de proteção — SSH, Fail2Ban e iptables —
e deixa o firewall pronto para coexistir com o Docker sem o UFW atrapalhar.

## Visão geral

| Camada | O que faz | Estado final |
|---|---|---|
| SSH | Força chave pública, desativa senha, libera apenas `root`. | `Port 22`, `PermitRootLogin prohibit-password`, `PasswordAuthentication no` |
| Fail2Ban | Banir 1 h após 3 falhas em 10 min. | Jail `sshd` ativo, usando `iptables-multiport` |
| iptables host | Input padrão `DROP`, abre TCP 22, 80 e 443 por padrão. | Chains `INPUT`/`FORWARD`/`OUTPUT` em `/etc/iptables/secure-host.v{4,6}` |
| iptables Docker | `DOCKER-USER` salta para `VPS-DOCKER`, que libera TCP 80/443 por padrão e bloqueia outras portas publicadas sem `open-port`. | Chains `VPS-DOCKER`/`VPS-DOCKER-ALLOW` em `/etc/iptables/secure-docker.v{4,6}` |
| UFW | Removido por padrão. | O pacote `ufw` é purgado (não apenas desativado) |

Docker continua dono de `NAT`, `DOCKER`, `DOCKER-BRIDGE`, etc. O script só
interfere na chain `DOCKER-USER` — ponto oficialmente documentado para
políticas do host em cima do Docker.

## Pré-requisitos

- Ubuntu 22.04, 24.04 ou 26.04 com `systemd`.
- Executar como `root` (`sudo ./secure-server.sh`).
- `/root/.ssh/authorized_keys` válido, com permissões seguras
  (`700` em `/root` e `/root/.ssh`, `600` em `authorized_keys`).
- Ao menos uma chave do root sem `command=` (imagens cloud costumam restringir
  a chave com `command="echo Please login as..."`).
- SSH somente na porta 22, inclusive no `ssh.socket`.
- Rota padrão fora de `docker0`, `docker_gwbridge` e `br-*`.
- Redes Docker com o nome padrão de bridge (`br-<id>`): bridges com nome
  customizado não são tratadas como internas.
- Nenhum dos seguintes em uso: `firewalld`, `nftables.service`,
  Docker com `"iptables": false` ou backend `"nftables"`.
- Conexão com a internet para `apt-get install` (caso `openssh-server`,
  `fail2ban`, `python3-systemd`, `iptables` ou `conntrack` ainda não estejam
  instalados).

> O script aborta com mensagem clara se algum desses pré-requisitos falhar.

## Como rodar

````bash
sudo ./secure-server.sh install
# Para ver ajuda (também é o comportamento sem subcomando):
sudo ./secure-server.sh --help
````

`install` é idempotente: pode rodar de novo e o resultado será equivalente
(regras regravadas, serviços apenas recarregados, backup novo criado).

## O que o script faz, passo a passo

1. **Valida o ambiente** — root, Ubuntu LTS correto, `systemd` ativo,
   `/root/.ssh/authorized_keys` válido, permissões seguras, ausência de
   `firewalld`/`nftables`/Docker em modo incompatível.
2. **Trava a execução** com `flock` em `/run/lock/secure-server.lock`.
3. **Captura o estado inicial** — status de `ssh`, `fail2ban`, `ufw` e a
   presença do pacote `ufw`. Tudo é gravado em `/var/backups/secure-server/<timestamp>/initial-state`.
4. **Faz backup** dos arquivos que serão modificados
   (`/etc/ssh/sshd_config`, drop-ins, jails, regras `iptables-save`, etc.).
5. **Garante pacotes**: `openssh-server`, `fail2ban`, `python3-systemd`, `iptables` e `conntrack`.
6. **Configura SSH** via drop-in `/etc/ssh/sshd_config.d/00-secure-server.conf`
   e recarrega o serviço.
7. **Configura o firewall**:
   - Grava `/etc/iptables/secure-host.v4` e `.v6`.
   - Grava `/etc/iptables/secure-docker.v4` e `.v6`.
   - Testa cada arquivo com `iptables-restore --test --noflush`.
   - **Purga o pacote `ufw`** se ele estava instalado, garantindo que
     nenhuma ferramenta futura reative um firewall conflitante.
   - Cria o serviço `secure-host-firewall.service` (carrega `host.v4`/`.v6`
     no boot, antes do `docker.service`).
   - Cria o drop-in `/etc/systemd/system/docker.service.d/10-secure-firewall.conf`
     que reaplica as chains `VPS-DOCKER`/`VPS-DOCKER-ALLOW` e o salto
     `DOCKER-USER → VPS-DOCKER` toda vez que o Docker inicia.
   - Aplica as regras imediatamente se o Docker já estiver ativo.
   - Configura `1.1.1.1` e `8.8.8.8` como DNS padrão dos containers,
     preservando outras opções de `daemon.json`; se houver mudança, reinicia o
     Docker uma vez para aplicá-la.
8. **Configura Fail2Ban** — escreve `/etc/fail2ban/jail.local`, remove o
   legacy `/etc/fail2ban/jail.d/sshd.local`, valida com `fail2ban-client -t`,
   reinicia o serviço e confere que a jail `sshd` subiu.
9. **Imprime relatório final** com `iptables -S`, status do Fail2Ban e
   localização do backup.

## Estrutura de arquivos criados

````
/etc/ssh/sshd_config.d/00-secure-server.conf
/etc/fail2ban/jail.local
/etc/iptables/secure-host.v4
/etc/iptables/secure-host.v6
/etc/iptables/secure-docker.v4
/etc/iptables/secure-docker.v6
/etc/systemd/system/secure-host-firewall.service
/etc/systemd/system/docker.service.d/10-secure-firewall.conf
/var/backups/secure-server/<UTC-timestamp>/
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
- Se o `ufw` estava instalado no estado inicial, tenta reinstalar o pacote e
  restaurar `/etc/ufw` antes de reativá-lo.
- Desabilita `secure-host-firewall` se ele não estava habilitado e reinicia o
  Docker se o `install` o tiver reiniciado.

Saídas por validação (`die`) depois do início das alterações também revertem.

Se algo der errado durante a reversão, o backup fica em
`/var/backups/secure-server/<timestamp>/` para inspeção manual.

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

### Docker (chain `DOCKER-USER` → `VPS-DOCKER`)

Para tráfego encaminhado a containers, Docker consulta a chain
`DOCKER-USER`. Quando o pacote chega a essa chain, o DNAT de uma porta
publicada já ocorreu; por isso as regras usam `conntrack --ctorigdstport`
para comparar a porta original do host. O script instala:

A lógica segue a documentação oficial do Docker sobre
[firewall com iptables](https://docs.docker.com/engine/network/firewall-iptables/).

````
-A DOCKER-USER -j VPS-DOCKER          # injetado pelo drop-in do docker.service
-A VPS-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A VPS-DOCKER -i docker0 -j RETURN    # trafego interno docker0
-A VPS-DOCKER -i br-+ -j RETURN        # trafego interno em bridges user-defined
-A VPS-DOCKER -i docker_gwbridge -j ACCEPT # trafego de saida Docker Swarm
-A VPS-DOCKER -j VPS-DOCKER-ALLOW
-A VPS-DOCKER -j DROP
-A VPS-DOCKER-ALLOW -p tcp --ctorigdstport 80 -j ACCEPT
-A VPS-DOCKER-ALLOW -p tcp --ctorigdstport 443 -j ACCEPT
# BEGIN secure-server managed ports
# Regras adicionadas por open-port, por exemplo:
# -A VPS-DOCKER-ALLOW -p tcp -m conntrack --ctstate NEW --ctorigdstport 6379 -j ACCEPT
# END secure-server managed ports
-A VPS-DOCKER-ALLOW -j RETURN
````

Pontos-chave:

- Apenas a porta de destino **publicada** no host (`--ctorigdstport`) é
  avaliada — é assim que Docker distingue "pacote chegou na porta 5400"
  vs "pacote chegou na 80".
- Conexões estabelecidas/relacionadas passam direto. Ao executar
  `close-port`, o script remove com `conntrack` os estados existentes da porta
  nos fluxos IPv4 e IPv6, para que clientes persistentes não permaneçam
  conectados.
- Pacotes vindos de uma bridge do Docker (`br-+`) voltam antes do
  bloqueio, evitando loop com regras do próprio Docker.
- Tráfego originado em `docker_gwbridge` é aceito antes do bloqueio: é a
  bridge interna de saída usada por serviços Docker Swarm, como Dokploy. A
  condição de interface não aceita tráfego que venha da WAN.
- As portas 22, 80 e 443/tcp são fixas: `open-port` e `close-port` recusam
  essas portas sem alterar nada.
- `open-port` e `close-port` preservam os saltos `f2b-*` do `INPUT`, mantendo
  os bans ativos. Outras regras adicionadas ao `INPUT` são descartadas.
- As chains são carregadas antes e depois do `dockerd` iniciar.
- Regras criadas por `open-port` ficam antes do `RETURN` terminal. A mesma
  operação também cria a regra equivalente no `INPUT` do host; `close-port`
  remove ambas de forma idempotente.

### Containers acessando o host

Por padrão, o `INPUT` aceita qualquer tráfego recebido por `docker0`, `br-+` e
`docker_gwbridge`. Assim, containers Docker, Compose e Swarm podem acessar
serviços no host via `172.17.0.1` sem executar `open-port`; isso não expõe a
porta à Internet porque a regra depende da interface interna. A consequência
é que um container local pode tentar acessar outros serviços que escutem no
host. Para algo que deva ser exclusivo do host, faça-o escutar em `127.0.0.1`
ou aplique uma política própria.

## Pontos a monitorar
- **IPv6 desativado no kernel** (`ipv6.disable=1`): as etapas de `ip6tables`
  são ignoradas. Se reativar o IPv6, rode `install` de novo.
- **Cloud-init / unattended-upgrades** podem reinstalar `ufw` em
  algumas imagens Ubuntu. Se isso acontecer, rode o script de novo —
  ele vai detectar e purgar de novo.
- **Drop-in do Docker**: editar
  `/etc/systemd/system/docker.service.d/10-secure-firewall.conf`
  é seguro, mas lembre que o script regrava esse arquivo a cada
  execução. Coloque mudanças persistentes em uma camada superior.
- **DNS dos containers**: o script usa `1.1.1.1` e `8.8.8.8` no
  `daemon.json`, para não herdar um DNS de VPN acessível apenas pelo host.
  Nomes internos da VPN não serão resolvidos por containers por padrão.
- **`/etc/docker/daemon.json`**: nunca defina `"iptables": false` ou
  `"firewall-backend": "nftables"` — o script aborta imediatamente.
