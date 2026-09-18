# Como abrir e fechar portas

O `secure-efa-server.sh` agora é um utilitário com subcomandos. O setup
inicial continua valendo — `install` aplica SSH, Fail2Ban, iptables e
dropa o `ufw`. Depois disso, **abrir e fechar portas é uma única linha**
que persiste no boot.

## Forma rápida (CLI)

````bash
# Setup inicial (uma vez):
sudo ./secure-efa-server.sh install

# Abrir porta:
sudo ./secure-efa-server.sh open-port 5400         # TCP 5400 (detecta Docker vs host)
sudo ./secure-efa-server.sh open-port 53/udp       # UDP 53
sudo ./secure-efa-server.sh open-port 9000 --force # forçar como porta de host

# Fechar porta:
sudo ./secure-efa-server.sh close-port 5400
sudo ./secure-efa-server.sh close-port 53/udp

# Auditar:
sudo ./secure-efa-server.sh list-ports
sudo ./secure-efa-server.sh list-ports --docker
sudo ./secure-efa-server.sh list-ports --host
````

### Detecção automática Docker vs host

`open-port` consulta `docker ps` para saber se a porta está publicada
por algum container. O resultado da inspeção determina em qual chain a
regra vai entrar:

| Caso | Escopo | Onde a regra é inserida |
|---|---|---|
| Algum container publica `<porta>/<proto>` na WAN | `docker` | `EFA-DOCKER-ALLOW` (antes do `COMMIT` em `/etc/iptables/secure-efa-docker.v4` e `.v6`) |
| Nenhum container publica essa porta | `host` | `INPUT` (em `/etc/iptables/secure-efa-host.v4` e `.v6`) |
| Você quer abrir como host mesmo havendo container | `host` (forçado) | `INPUT`, com `--force` |

A regra **vale imediatamente** no kernel (v4 e v6) e **persiste no boot**
porque o arquivo base é regenerado de forma atômica a cada chamada.

### Estado canônico

As portas gerenciadas ficam registradas em
`/etc/iptables/secure-efa-allowed-ports.list` no formato
`<porta>\t<proto>\t<escopo>\t<origem>`. Esse arquivo é a fonte de
verdade: `open-port`/`close-port` o editam e depois regeneram os
arquivos `.v4`/`.v6`.

`list-ports` lê esse arquivo e formata a saída. Cada operação cria
um snapshot em `/var/backups/secure-efa-server/open-port-<timestamp>/`
para auditoria.

## Forma manual (legado) — quando ainda faz sentido

Os comandos `iptables` manuais continuam funcionando — o drop-in do
`docker.service` mantém o salto `DOCKER-USER → EFA-DOCKER` ativo e não
apaga regras inseridas fora dele. Mas qualquer regra manual **se perde
no próximo `open-port`/`close-port`**, porque o utilitário regenera os
arquivos `.v4`/`.v6` a partir do arquivo canônico.

Use a forma manual só se quiser uma regra temporária que não sobreviva
ao próximo `open-port`:

````bash
# Porta Docker temporaria (sobrevive a restart do docker, some no reboot
# e no proximo open-port/close-port):
sudo iptables -I EFA-DOCKER-ALLOW 1 \
  -p tcp -m conntrack --ctstate NEW --ctorigdstport 5400 -j ACCEPT

# Porta de host temporaria:
sudo iptables -I INPUT 1 \
  -p tcp -m conntrack --ctstate NEW --dport 9000 -j ACCEPT
````

## Editar manualmente os arquivos base (avançado)

Se você editar `/etc/iptables/secure-efa-host.v{4,6}` ou
`/etc/iptables/secure-efa-docker.v{4,6}` direto:

1. Mantenha o bloco entre `# BEGIN secure-efa-server managed ports`
   e `# END secure-efa-server managed ports` intacto se quiser que o
   utilitário continue entendendo o estado. Linhas fora desse bloco
   são tratadas como "pre-existentes" e preservadas.
2. Rode `sudo iptables-restore --test --noflush < arquivo` antes de
   aplicar, para validar a sintaxe.
3. Para aplicar imediatamente:

   ````bash
   sudo systemctl reload secure-efa-host-firewall     # arquivos host.v*
   sudo iptables-restore --noflush < /etc/iptables/secure-efa-docker.v4
   sudo ip6tables-restore --noflush < /etc/iptables/secure-efa-docker.v6
   ````

4. Se quiser que a edição manual **persista** entre `open-port`/
   `close-port`, registre-a também em `/etc/iptables/secure-efa-allowed-ports.list`
   para que o utilitário não a remova na próxima regeneração.

## Diagnóstico

| Sintoma | Onde olhar |
|---|---|
| `open-port 5400` diz "nenhum container publica esta porta" mas você queria Docker | Verifique `docker ps --format '{{.Ports}}'` e se o container está rodando. |
| Porta não responde da WAN | `sudo iptables -nvL INPUT` e `sudo iptables -nvL EFA-DOCKER-ALLOW`. |
| Regras somem após reboot | Confirme `systemctl status secure-efa-host-firewall` e que `secure-efa-allowed-ports.list` está preenchido. |
| `open-port 5400` duplica regras | O utilitário limpa ocorrências anteriores da mesma porta antes de inserir. Se ainda ver duplicatas, rode `close-port 5400` e depois `open-port 5400` novamente. |
| IPv6 não responde | Rode `ip6tables-restore --test --noflush < /etc/iptables/secure-efa-host.v6` (e o equivalente docker). Se passar, `sudo ip6tables-restore --noflush < …`. |
| Docker não sobe após `install` | O drop-in reaplica o salto a cada restart do Docker; veja `journalctl -u docker --no-pager`. |

## Receitas rápidas

### Liberar Postgres exposto na 5432 (Docker)

````bash
sudo ./secure-efa-server.sh open-port 5432
sudo ./secure-efa-server.sh list-ports --docker
````

### Liberar DNS público (UDP 53)

````bash
sudo ./secure-efa-server.sh open-port 53/udp
````

### Liberar app de monitoramento do host na 9090

````bash
sudo ./secure-efa-server.sh open-port 9090 --force
sudo ./secure-efa-server.sh list-ports --host
````

### Reverter tudo

````bash
sudo ./secure-efa-server.sh close-port 5432
sudo ./secure-efa-server.sh close-port 53/udp
sudo ./secure-efa-server.sh close-port 9090
sudo ./secure-efa-server.sh list-ports
````

O utilitário **sempre** persiste imediatamente; não há flag
`--no-persist`. Para uma regra efêmera, use os comandos manuais da
seção "Forma manual".