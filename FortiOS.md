# FortiOS

## Índice

- [Sistema e Status](#sistema-e-status)
- [Roteamento](#roteamento)
- [ARP](#arp)
- [Sessões](#sessões)
- [Ping / Traceroute / Telnet](#ping--traceroute--telnet)
- [Sniffer de Pacotes](#sniffer-de-pacotes)
- [Debug Flow](#debug-flow)
- [VPN IPSec (Site-to-Site)](#vpn-ipsec-site-to-site)
- [SSL VPN](#ssl-vpn)
- [SAML](#saml)
- [Autenticação de Usuário SSL](#autenticação-de-usuário-ssl)
- [FSSO](#fsso)
- [DHCP](#dhcp)
- [Web Filter](#web-filter)
- [BGP](#bgp)
- [HA (High Availability)](#ha-high-availability)
- [Link Monitor / SD-WAN](#link-monitor--sd-wan)
- [Firewall Policy](#firewall-policy)
- [Automation Stitch](#automation-stitch)
- [Interfaces e Hardware](#interfaces-e-hardware)
- [API REST](#api-rest)

---

## Sistema e Status

### Status geral do sistema
```fortios
get sys status
```

### Status do HA
```fortios
get sys ha status
```

### Informações globais do sistema
```fortios
get system global
```

### Configurações do sistema (grupo de security profile na GUI)
```fortios
config system settings
    set gui-security-profile-group enable
end
```

### Ler crashlog
```fortios
diag debug crashlog read
```

### Ler log de erro de configuração
```fortios
diagnose debug config-error-log read
```

### Consumo de CPU / Memória (conserve mode)
```fortios
get sys status
diag sys top 5 30
```
> Durante a execução: `c` ordena por CPU, `m` ordena por memória, `q` encerra. Roda a cada 5s por 30 ciclos.

```fortios
diag sys top 5 30 3
get hardware memory
diag sys top-mem 10
diag sys top-mem detail
```

### Deviceinfo de uma NIC
```fortios
diag hardware deviceinfo nic lan1
```

### Teste de velocidade da interface
```fortios
diagnose traffictest run
```

---

## Roteamento

### Detalhes da tabela de rotas para um IP
```fortios
get router info routing-table details 192.168.1.99
```

### Resumo BGP
```fortios
get router info bgp summary
```

### Limpar sessão BGP (soft, direção in)
```fortios
execute router clear bgp ip 10.2.0.250 soft in
```

---

## ARP

### Tabela ARP inteira do firewall
```fortios
get system arp
```

### Verificar se um IP específico está na rede
```fortios
show | grep <IP-da-rede>
```

---

## Sessões

### Listar sessões ativas
```fortios
diagnose sys session list
```

### Limpar todas as sessões
```fortios
diagnose sys session clear
```

### Deletar sessão específica por ID
```fortios
diagnose sys session delete <ID-da-sessão>
```

### Filtrar por IP de destino antes de limpar
```fortios
diagnose sys session filter dst 10.3.79.165 10.3.79.185
diagnose sys session clear
```

### Filtrar por IP de origem antes de limpar
```fortios
diagnose sys session filter scr 10.3.79.165 10.3.79.185
diagnose sys session clear
```

---

## Ping / Traceroute / Telnet

### Ping padrão
```fortios
exec ping 192.168.0.1
```

### Ping usando IP de origem específico
> Só funciona com IPs que são de interface presente no firewall.
```fortios
exec ping-options source 10.11.100.232
```

### Traceroute
```fortios
exec traceroute 10.11.100.232
```

### Telnet (teste de porta)
```fortios
exec telnet 10.11.100.232 22
```

---

## Sniffer de Pacotes

### Por host
```fortios
diagnose sniffer packet any "host 10.211.12.68" 4
```

### Host + protocolo (ICMP)
```fortios
diagnose sniffer packet any "host 201.55.34.141 and icmp" 4
```

### Origem e destino específicos
```fortios
diagnose sniffer packet any "host 201.55.34.141 and host 10.211.12.68" 4
```

---

## Debug Flow

### Fluxo básico de debug (genérico)
```fortios
diagnose debug disable
diagnose debug flow trace stop
diagnose debug flow filter clear
diagnose debug flow filter saddr 10.44.114.36
diagnose debug flow filter daddr 10.200.24.10
diagnose debug flow filter dport 5060
diagnose debug flow show console enable
diagnose debug flow show function-name enable
diagnose debug flow show iprope enable
diagnose debug console timestamp enable
diagnose debug flow trace start 9999
diagnose debug enable
```

### Filtros disponíveis (`diagnose debug flow filter ?`)

| Opção | Descrição |
|---|---|
| `clear` | Limpa o filtro. |
| `vd` | Índice do virtual domain (VDOM). |
| `vd-name` | Nome do virtual domain (VDOM). |
| `proto` | Número do protocolo (ex.: 1=ICMP, 6=TCP, 17=UDP). |
| `addr` | Endereço IP (origem ou destino). |
| `saddr` | Endereço IP de origem. |
| `daddr` | Endereço IP de destino. |
| `port` | Porta (origem ou destino). |
| `sport` | Porta de origem. |
| `dport` | Porta de destino. |
| `negate` | Inverte o filtro (nega a condição informada). |

### Exemplos de uso
```fortios
diagnose debug flow filter clear
diagnose debug flow filter vd 0
diagnose debug flow filter vd-name root
diagnose debug flow filter proto 6
diagnose debug flow filter addr 10.253.106.101
diagnose debug flow filter addr 10.253.106.101 10.130.89.95
diagnose debug flow filter saddr 177.92.88.242
diagnose debug flow filter daddr 10.0.4.133
diagnose debug flow filter port 5060
diagnose debug flow filter sport 5060
diagnose debug flow filter dport 5060
diagnose debug flow filter negate saddr 10.44.114.36
```

### Encerrar debug
```fortios
diagnose debug disable
```

### Fluxo completo com iprope (visualiza lookup de rota)
```fortios
diagnose debug disable
diagnose debug flow trace stop
diagnose debug flow filter clear
diagnose debug flow show iprope enable
diagnose debug flow filter dport 514
diagnose debug flow show console enable
diagnose debug flow show function-name enable
diagnose debug console timestamp enable
diagnose debug flow trace start 999999
diagnose debug enable
```

### iprope lookup direto (sem trace)
```fortios
diag firewall iprope lookup 172.20.100.5 0 172.20.142.50 8400 6 RT_DMZ-ROOT0
```

### Ver interfaces via fnsysctl
```fortios
fnsysctl ifconfig interface
```

### Lista de endereços IP conhecidos
```fortios
diagnose ip address list
```

### Ver zona de sistema (VLANs)
```fortios
show sys zone | grep VLAN
```

---

## VPN IPSec (Site-to-Site)

### Debug de negociação IKE
```fortios
diagnose debug disable
diagnose debug reset
diagnose vpn ike log-filter dst-addr4 192.168.10.164
diagnose vpn ike log-filter rem-addr4 10.44.120.1
diag debug application ike -1
diagnose debug console timestamp enable
diagnose debug enable
```

### Verificar se a fase 1 está estabelecida
```fortios
diag vpn ike gateway list name "VPN_NAME"
```

### Resumo de túneis (fase 1 e fase 2)
```fortios
get vpn ipsec tunnel summary | grep -i -f "VPN_NAME"
```

---

## SSL VPN

### Debug geral SSL VPN
```fortios
dia debug en
dia debug reset
diag debug app fnbamd 255
```

### Listar e derrubar sessões SSL VPN
```fortios
execute vpn sslvpn list
execute vpn sslvpn del-all
```

---

## SAML

### Debug de autenticação SAML
```fortios
diagnose debug application httpsd -1
diagnose debug application samld -1
diagnose debug console timestamp enable
diagnose debug enable
```

---

## Autenticação de Usuário SSL

### Debug padrão (usuário/senha local)
```fortios
diag deb reset
diag deb console timestamp enable
diag deb application fnbamd -1
diag deb application authd -1
diag deb application sslvpn -1
diag deb enable
```

### Debug com SAML
```fortios
diagnose vpn ssl debug-filter src-addr
diagnose debug application samld -1
diagnose debug application sslvpn -1
diagnose debug enable
```

---

## FSSO

### Status do servidor FSSO
```fortios
diagnose debug enable
diagnose debug authd fsso server-status
```

---

## DHCP

### Debug do serviço DHCP
```fortios
diag debug reset
diag debug application dhcps -1
diag debug enable
```

### Encerrar debug
```fortios
diag debug reset
diag debug disable
```

---

## Web Filter

### Testar conectividade com FortiGuard
```fortios
diagnose debug rating
exec ping service.fortiguard.net
exec ping update.fortiguard.net
exec ping guard.fortinet.net
```

### Ver categoria de webfilter nos logs
```fortios
execute log filter category utm-webfilter
execute log display
```

### Debug de atualização de rating/database
```fortios
diag debug application update -1
diag debug enable
exec update-now
```

### Buscar FQDN em listas de firewall
```fortios
diag firewall fqdn list | grep -i -f youtube
```

### Criar tabela de URL Filter customizada
```fortios
show webfilter profile
config web
    set urlfilter-table 0
    edit 0
        set name "RAVPN-WEB-PROF"
        config entries
            edit 1
                set url "*.qualys.com"
                set type wildcard
            next
            edit 2
                set url "*.santandergatewayft.com.br"
                set type wildcard
            next
            edit 3
                set url "download.docker.com"
                set type wildcard
            next
        end
    next
end
```
> Padrão: `set type wildcard` para domínios com `*`; URLs exatas (sem wildcard) não precisam do `set type`.

---

## BGP

Ver seção [Roteamento](#roteamento) acima.

---

## HA (High Availability)

### Assumir gerência de um nó HA
```fortios
exec ha manage 0 jusantos
```

### Definir prioridade de um nó
```fortios
exec ha set-priority FG4H0E5819900156 151
```

### Resetar uptime do HA (forçar reeleição)
```fortios
diagnose sys ha reset-uptime
```

---

## Link Monitor / SD-WAN

### Criar probe de link monitor
```fortios
config system link-monitor
    edit "ProbeMPLS"
        set srcintf port1
        set gateway-ip 10.112.36.194
        set server 10.41.122.2
    next
end
```

---

## Firewall Policy

### Mover regra de posição
```fortios
move 956 before 905
move 501 before 87
```

---

## Automation Stitch

### Debug de automation não disparando
```fortios
diagnose debug reset
diagnose debug application autod -1
diagnose debug enable
```

---

## Interfaces e Hardware

Ver [Sistema e Status](#sistema-e-status) para deviceinfo de NIC e teste de velocidade.

---

## API REST

### Ver senha em texto plano de uma VPN IPSec (phase1-interface)
```
https://<IP-do-firewall>:11443/api/v2/cmdb/vpn.ipsec/phase1-interface/<NOME-DA-VPN>?plain-text-password=1
```

**Exemplos:**
```
https://192.168.253.253:11443/api/v2/cmdb/vpn.ipsec/phase1-interface/VPN_DC-01?plain-text-password=1
https://192.168.1.99:11443/api/v2/cmdb/vpn.ipsec/phase1-interface/VPN_DC-WCS?plain-text-password=1
```

---

## Sudo: executar comandos entre VDOMs

```fortios
sudo FILIAIS get router info routing-table details x.x.x.x
```
