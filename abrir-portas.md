# Como abrir e fechar portas

O `secure-server.sh` agora é um utilitário com subcomandos. O setup
inicial continua valendo — `install` aplica SSH, Fail2Ban, iptables e
dropa o `ufw`. Depois disso, **abrir e fechar portas é uma única linha**
que persiste no boot.

Durante `install`, Docker recebe `1.1.1.1` e `8.8.8.8` como DNS padrão dos
containers. Isso evita que builds herdem um DNS de VPN utilizável apenas pelo
host. Se essa configuração mudar, Docker é reiniciado uma vez.

## Forma rápida (CLI)

````bash
# Setup inicial (uma vez):
sudo ./secure-server.sh install

# Abrir porta:
sudo ./secure-server.sh open-port 5400         # TCP 5400 no host e no Docker
sudo ./secure-server.sh open-port 53/udp       # UDP 53
sudo ./secure-server.sh open-port 9000         # TCP 9000 no host e no Docker

# Fechar porta:
sudo ./secure-server.sh close-port 5400
sudo ./secure-server.sh close-port 53/udp

# Auditar:
sudo ./secure-server.sh list-ports
sudo ./secure-server.sh list-ports --docker
sudo ./secure-server.sh list-ports --host
````

### Uma operação, dois caminhos de tráfego

`open-port` sempre registra e aplica a mesma `<porta>/<protocolo>` nos
dois escopos. Isso evita que uma porta funcione para o processo local, mas
não para um container (ou o inverso):

| Escopo | Regra aplicada | Tráfego atendido |
|---|---|---|
| `host` | `INPUT ... --dport <porta> -j ACCEPT` | Processo escutando diretamente no servidor |
| `docker` | `VPS-DOCKER-ALLOW ... --ctorigdstport <porta> -j ACCEPT` | Porta publicada por um container Docker |

Não é necessário que um container já publique a porta quando você executa
`open-port`: a política Docker fica persistida e passa a valer assim que uma
publicação correspondente existir. A regra não cria publicação/NAT no Docker;
ela somente permite o tráfego caso o Docker a publique.

### Container para serviço no host, sem exposição pública

Quando um container acessa um serviço pelo gateway do host — por exemplo,
`POSTGRES_HOST=172.17.0.1` e `POSTGRES_PORT=5236` — uma tarefa Swarm entra no
host pela `docker_gwbridge`. Isso já é permitido por padrão, sem comando de
porta: o firewall aceita tráfego que entra por `docker0`, `br+` (Compose) e
`docker_gwbridge` (Swarm). Essas são interfaces locais, então a permissão não
libera nenhuma porta na interface pública nem para a Internet.

Consequência deliberada: qualquer container local pode tentar se conectar a
qualquer serviço escutando no host. Portanto, processos administrativos que
devem ser exclusivos do host precisam escutar somente em `127.0.0.1` ou ter
uma política adicional própria.

No longo prazo, para serviços Swarm, prefira pôr app e banco numa mesma rede
overlay e conectar pelo nome do serviço e pela porta interna 5432. Assim não é
preciso publicar o banco nem depender de `172.17.0.1`.

O inverso também é verdadeiro: `docker run -p ...` ou `ports:` no Compose
**não** publica a porta para a Internet por si só. Sem a entrada explícita no
arquivo canônico criada por `open-port`, `VPS-DOCKER` a bloqueia. O próprio VPS
e containers na rede interna podem continuar acessando o serviço, pois isso
não é tráfego de entrada da WAN. As exceções base são TCP 80 e 443, que o
script mantém públicos para o proxy web, além de TCP 22 para SSH no host.

`close-port` remove os dois registros e reconstrói as duas políticas, mesmo
quando o arquivo de estado estiver incompleto. Assim também limpa regras
órfãs de versões anteriores. Ele também invalida, com `conntrack`, sessões
TCP/UDP já estabelecidas para essa porta; clientes conectados, como Redis
Insight, perdem a sessão na próxima troca de pacotes e não conseguem
reconectar externamente.

A regra **vale imediatamente** no kernel (v4 e v6) e **persiste no boot**
porque o arquivo base é regenerado de forma atômica a cada chamada.

### Estado canônico

As portas gerenciadas ficam registradas em
`/etc/iptables/secure-allowed-ports.list` no formato
quatro campos separados por **TAB real**: porta, protocolo, escopo e origem.
Esse arquivo é a fonte de
verdade: `open-port`/`close-port` o editam e depois regeneram os
arquivos `.v4`/`.v6`.

`list-ports` lê esse arquivo e formata a saída. Cada operação cria
um snapshot em `/var/backups/secure-server/open-port-<timestamp>/`
para auditoria.

## Forma manual (legado) — quando ainda faz sentido

Os comandos `iptables` manuais continuam funcionando — o drop-in do
`docker.service` mantém o salto `DOCKER-USER → VPS-DOCKER` ativo e não
apaga regras inseridas fora dele. Mas qualquer regra manual **se perde
no próximo `open-port`/`close-port`**, porque o utilitário regenera os
arquivos `.v4`/`.v6` a partir do arquivo canônico.

Use a forma manual só se quiser uma regra temporária que não sobreviva
ao próximo `open-port`:

````bash
# Porta Docker temporaria (sobrevive a restart do docker, some no reboot
# e no proximo open-port/close-port):
sudo iptables -I VPS-DOCKER-ALLOW 1 \
  -p tcp -m conntrack --ctstate NEW --ctorigdstport 5400 -j ACCEPT

# Porta de host temporaria:
sudo iptables -I INPUT 1 \
  -p tcp -m conntrack --ctstate NEW --dport 9000 -j ACCEPT
````

## Arquivos de regras e edição manual

Os arquivos `/etc/iptables/secure-host.v{4,6}` e
`/etc/iptables/secure-docker.v{4,6}` são reconstruídos integralmente a
partir da política fixa e do arquivo de estado canônico. Não edite esses
arquivos para criar uma permissão persistente: a próxima chamada de
`open-port` ou `close-port` substituirá a edição. Para permissões persistentes,
use sempre a CLI.

## Diagnóstico

| Sintoma | Onde olhar |
|---|---|
| Porta não responde da WAN | `sudo iptables -nvL INPUT` e `sudo iptables -nvL VPS-DOCKER-ALLOW`. |
| Regras somem após reboot | Confirme `systemctl status secure-host-firewall` e que `secure-allowed-ports.list` está preenchido. |
| `open-port 5400` parece não expor um container | Confirme que o container realmente publicou a porta (`docker ps`); o comando libera o firewall, mas não cria a publicação Docker. |
| `open-port 5400` duplica regras | Rode a versão atual do script; a operação é idempotente e reconstroi as regras a partir do estado canônico. |
| IPv6 não responde | Rode `ip6tables-restore --test --noflush < /etc/iptables/secure-host.v6` (e o equivalente docker). Se passar, `sudo ip6tables-restore --noflush < …`. |
| Docker não sobe após `install` | O drop-in reaplica o salto a cada restart do Docker; veja `journalctl -u docker --no-pager`. |

## Receitas rápidas

### Liberar Postgres exposto na 5432 (Docker)

````bash
sudo ./secure-server.sh open-port 5432
sudo ./secure-server.sh list-ports --docker
````

### Liberar DNS público (UDP 53)

````bash
sudo ./secure-server.sh open-port 53/udp
````

### Liberar app de monitoramento na 9090

````bash
sudo ./secure-server.sh open-port 9090
sudo ./secure-server.sh list-ports
````

### Reverter tudo

````bash
sudo ./secure-server.sh close-port 5432
sudo ./secure-server.sh close-port 53/udp
sudo ./secure-server.sh close-port 9090
sudo ./secure-server.sh list-ports
````

O utilitário **sempre** persiste imediatamente; não há flag
`--no-persist`. Para uma regra efêmera, use os comandos manuais da
seção "Forma manual".
