# FortiOS

## Index

- [System and Status](#system-and-status)
- [Routing](#routing)
- [ARP](#arp)
- [Sessions](#sessions)
- [Ping / Traceroute / Telnet](#ping--traceroute--telnet)
- [Packet Sniffer](#packet-sniffer)
- [Debug Flow](#debug-flow)
- [IPSec VPN (Site-to-Site)](#ipsec-vpn-site-to-site)
- [SSL VPN](#ssl-vpn)
- [SAML](#saml)
- [SSL User Authentication](#ssl-user-authentication)
- [FSSO](#fsso)
- [DHCP](#dhcp)
- [Web Filter](#web-filter)
- [BGP](#bgp)
- [HA (High Availability)](#ha-high-availability)
- [Link Monitor / SD-WAN](#link-monitor--sd-wan)
- [Firewall Policy](#firewall-policy)
- [Automation Stitch](#automation-stitch)
- [Interfaces and Hardware](#interfaces-and-hardware)
- [REST API](#rest-api)
- [Sudo (Cross-VDOM Commands)](#sudo-cross-vdom-commands)

---

## System and Status

### General system status
```fortios
get sys status
```

### HA status
```fortios
get sys ha status
```

### Global system info
```fortios
get system global
```

### System settings (GUI security profile group)
```fortios
config system settings
    set gui-security-profile-group enable
end
```

### Read crashlog
```fortios
diag debug crashlog read
```

### Read config error log
```fortios
diagnose debug config-error-log read
```

### CPU / memory usage (conserve mode)
```fortios
get sys status
diag sys top 5 30
```
> `c`=CPU, `m`=memória, `q`=sair. Roda a cada 5s, por 30 ciclos.

```fortios
diag sys top 5 30 3
get hardware memory
diag sys top-mem 10
diag sys top-mem detail
```

### NIC device info
```fortios
diag hardware deviceinfo nic lan1
```

### Interface speed test
```fortios
diagnose traffictest run
```

---

## Routing

### Route table details for an IP
```fortios
get router info routing-table details 192.168.1.99
```

### BGP summary
```fortios
get router info bgp summary
```

### Clear BGP session (soft, inbound)
```fortios
execute router clear bgp ip 10.2.0.250 soft in
```

---

## ARP

### Full ARP table
```fortios
get system arp
```

### Check if an IP is on the network
```fortios
show | grep <IP-da-rede>
```

---

## Sessions

### List active sessions
```fortios
diagnose sys session list
```

### Clear all sessions
```fortios
diagnose sys session clear
```

### Delete a session by ID
```fortios
diagnose sys session delete <ID-da-sessão>
```

### Filter by destination IP before clearing
```fortios
diagnose sys session filter dst 10.3.79.165 10.3.79.185
diagnose sys session clear
```

### Filter by source IP before clearing
```fortios
diagnose sys session filter scr 10.3.79.165 10.3.79.185
diagnose sys session clear
```

---

## Ping / Traceroute / Telnet

### Basic ping
```fortios
exec ping 192.168.0.1
```

### Ping with a specific source IP
> Só funciona com IP de uma interface do firewall.
```fortios
exec ping-options source 10.11.100.232
```

### Traceroute
```fortios
exec traceroute 10.11.100.232
```

### Telnet (port test)
```fortios
exec telnet 10.11.100.232 22
```

---

## Packet Sniffer

### By host
```fortios
diagnose sniffer packet any "host 10.211.12.68" 4
```

### Host + protocol (ICMP)
```fortios
diagnose sniffer packet any "host 201.55.34.141 and icmp" 4
```

### Specific source and destination
```fortios
diagnose sniffer packet any "host 201.55.34.141 and host 10.211.12.68" 4
```

---

## Debug Flow

### Basic debug flow (generic)
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

### Available filters (`diagnose debug flow filter ?`)

| Option | Descrição |
|---|---|
| `clear` | Limpa o filtro. |
| `vd` | Índice da VDOM. |
| `vd-name` | Nome da VDOM. |
| `proto` | Número do protocolo (1=ICMP, 6=TCP, 17=UDP). |
| `addr` | IP de origem ou destino. |
| `saddr` | IP de origem. |
| `daddr` | IP de destino. |
| `port` | Porta de origem ou destino. |
| `sport` | Porta de origem. |
| `dport` | Porta de destino. |
| `negate` | Inverte o filtro. |

### Usage examples
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

### Stop debug
```fortios
diagnose debug disable
```

### Full flow with iprope (route lookup)
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

### Iprope Lookup
```fortios
diag firewall iprope lookup 172.20.100.5 0 172.20.142.50 8400 6 RT_DMZ-ROOT0
```

### View interfaces via fnsysctl
```fortios
fnsysctl ifconfig interface
```

### List known IP addresses
```fortios
diagnose ip address list
```

### View system zone (VLANs)
```fortios
show sys zone | grep VLAN
```

---

## IPSec VPN (Site-to-Site)

### IKE negotiation debug
```fortios
diagnose debug disable
diagnose debug reset
diagnose vpn ike log-filter dst-addr4 192.168.10.164
diagnose vpn ike log-filter rem-addr4 10.44.120.1
diag debug application ike -1
diagnose debug console timestamp enable
diagnose debug enable
```

### Check if phase 1 is established
```fortios
diag vpn ike gateway list name "VPN_NAME"
```

### Tunnel summary (phase 1 and 2)
```fortios
get vpn ipsec tunnel summary | grep -i -f "VPN_NAME"
```

---

## SSL VPN

### General SSL VPN debug
```fortios
dia debug en
dia debug reset
diag debug app fnbamd 255
```

### List and drop SSL VPN sessions
```fortios
execute vpn sslvpn list
execute vpn sslvpn del-all
```

---

## SAML

### SAML authentication debug
```fortios
diagnose debug application httpsd -1
diagnose debug application samld -1
diagnose debug console timestamp enable
diagnose debug enable
```

---

## SSL User Authentication

### Default debug (local user/password)
```fortios
diag deb reset
diag deb console timestamp enable
diag deb application fnbamd -1
diag deb application authd -1
diag deb application sslvpn -1
diag deb enable
```

### Debug with SAML
```fortios
diagnose vpn ssl debug-filter src-addr
diagnose debug application samld -1
diagnose debug application sslvpn -1
diagnose debug enable
```

---

## FSSO

### FSSO server status
```fortios
diagnose debug enable
diagnose debug authd fsso server-status
```

---

## DHCP

### DHCP service debug
```fortios
diag debug reset
diag debug application dhcps -1
diag debug enable
```

### Stop debug
```fortios
diag debug reset
diag debug disable
```

---

## Web Filter

### Test FortiGuard connectivity
```fortios
diagnose debug rating
exec ping service.fortiguard.net
exec ping update.fortiguard.net
exec ping guard.fortinet.net
```

### View webfilter category in logs
```fortios
execute log filter category utm-webfilter
execute log display
```

### Rating/database update debug
```fortios
diag debug application update -1
diag debug enable
exec update-now
```

### Search FQDN in firewall lists
```fortios
diag firewall fqdn list | grep -i -f youtube
```

### Create a custom URL filter table
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
> `wildcard` para domínios com `*`; URL exata dispensa `set type`.

---

## BGP

Ver seção [Routing](#routing).

---

## HA (High Availability)

### Take over management of an HA node
```fortios
exec ha manage 0 jusantos
```

### Set node priority
```fortios
exec ha set-priority FG4H0E5819900156 151
```

### Reset HA uptime (force re-election)
```fortios
diagnose sys ha reset-uptime
```

---

## Link Monitor / SD-WAN

### Create a link monitor probe
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

### Reorder a rule
```fortios
move 956 before 905
move 501 before 87
```

---

## Automation Stitch

### Debug automation not triggering
```fortios
diagnose debug reset
diagnose debug application autod -1
diagnose debug enable
```
> Referência: [Fortinet Community — Technical Tip: How to check why automation stitch is not working](https://community.fortinet.com/fortigate-3/technical-tip-how-to-check-why-automation-stitch-is-not-working-as-expected-92733)

---

## Interfaces and Hardware

Ver [System and Status](#system-and-status) para deviceinfo de NIC e teste de velocidade.

---

## REST API

### View plaintext password for an IPSec VPN (phase1-interface)
```
https://<IP-do-firewall>:11443/api/v2/cmdb/vpn.ipsec/phase1-interface/<NOME-DA-VPN>?plain-text-password=1
```

**Exemplos:**
```
https://192.168.253.253:11443/api/v2/cmdb/vpn.ipsec/phase1-interface/VPN_DC-01?plain-text-password=1
https://192.168.1.99:11443/api/v2/cmdb/vpn.ipsec/phase1-interface/VPN_DC-WCS?plain-text-password=1
```

---

## Sudo (Cross-VDOM Commands)

```fortios
sudo FILIAIS get router info routing-table details x.x.x.x
```
