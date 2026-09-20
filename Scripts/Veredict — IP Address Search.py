#!/usr/bin/env python3
"""
ip_investigate.py
==================

Ferramenta de triagem técnica de IP para análise de ataques
(ex.: tentativas de brute-force / acesso indevido no FortiAuthenticator).

Consulta múltiplas fontes em paralelo, consolida internamente e entrega
um dossiê técnico. NÃO emite conclusões nem veredito — apenas dados.

FONTES CONSULTADAS
------------------
  Geolocalização / ASN
    - ipapi.is        geo, ASN, flags de risco (datacenter/VPN/proxy/Tor/abuser)
    - ip-api.com      geo, ASN, ISP, flags de proxy/hosting/mobile
    - ipwho.is        geo, ASN, conexão

  Registro / Roteamento
    - RDAP            WHOIS estruturado: bloco, status, datas, contatos de abuse
    - RIPEstat        prefixo anunciado em BGP, ASN de origem, visibilidade,
                      contatos de abuse autoritativos, overview do AS,
                      validação RPKI (ROA), blocklists históricas

  DNS
    - PTR             DNS reverso
    - FCrDNS          validação forward-confirmed (PTR -> A -> IP bate?)
    - DNSBL           6 blacklists, com código de retorno e significado
    - Tor DNSEL       consulta à lista oficial de exit nodes do Tor

  Propriedades do endereço
    - Classificação RFC (privado, reservado, multicast, link-local, etc)
    - Representações (inteiro, hex, binário, in-addr.arpa)
    - Redes /24 e /16 de contexto

USO
---
    python3 ip_investigate.py
    python3 ip_investigate.py 1.2.3.4
    python3 ip_investigate.py 1.2.3.4 --json        exporta JSON estruturado
    python3 ip_investigate.py 1.2.3.4 --detalhado   resposta crua de cada fonte
"""

import ipaddress
import json
import platform
import socket
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------

TIMEOUT = 10

# DNSBLs com o significado dos códigos de retorno mais comuns.
# O código retornado (127.0.0.X) indica o MOTIVO da listagem.
DNSBL_LIST = {
    "zen.spamhaus.org": {
        "descricao": "Spamhaus ZEN (SBL+CSS+XBL+PBL combinados)",
        "codigos": {
            "127.0.0.2": "SBL - Spamhaus Blocklist (fonte de spam conhecida)",
            "127.0.0.3": "SBL CSS - snowshoe spam / listagem automatizada",
            "127.0.0.4": "XBL - máquina comprometida / proxy aberto / worm",
            "127.0.0.5": "XBL - máquina comprometida (CBL)",
            "127.0.0.6": "XBL - máquina comprometida",
            "127.0.0.7": "XBL - máquina comprometida",
            "127.0.0.9": "SBL DROP/EDROP - bloco sequestrado ou criminoso",
            "127.0.0.10": "PBL - faixa residencial/dinâmica (não deve enviar SMTP)",
            "127.0.0.11": "PBL - faixa residencial/dinâmica (política do ISP)",
        },
    },
    "bl.spamcop.net": {
        "descricao": "SpamCop - denúncias de spam reportadas por usuários",
        "codigos": {"127.0.0.2": "Reportado como origem de spam"},
    },
    "b.barracudacentral.org": {
        "descricao": "Barracuda Reputation Block List",
        "codigos": {"127.0.0.2": "Reputação ruim (spam/abuso)"},
    },
    "dnsbl-1.uceprotect.net": {
        "descricao": "UCEPROTECT Level 1 - IP individual",
        "codigos": {"127.0.0.2": "IP individual envolvido em abuso"},
    },
    "dnsbl.sorbs.net": {
        "descricao": "SORBS - agregador de múltiplas listas",
        "codigos": {
            "127.0.0.2": "HTTP proxy aberto",
            "127.0.0.3": "SOCKS proxy aberto",
            "127.0.0.4": "Proxy aberto (diversos)",
            "127.0.0.5": "SMTP relay aberto",
            "127.0.0.6": "Origem de spam",
            "127.0.0.7": "Formulário web explorável",
            "127.0.0.8": "Host que permite spam (política)",
            "127.0.0.9": "Bloco sequestrado / rota ilegal",
            "127.0.0.10": "IP dinâmico/residencial",
            "127.0.0.11": "Sem PTR válido / PTR genérico",
            "127.0.0.12": "Política: não aceita e-mail de servidor não autorizado",
            "127.0.0.14": "Zumbi / máquina comprometida",
        },
    },
    "cbl.abuseat.org": {
        "descricao": "CBL (Composite Blocking List) - máquinas infectadas",
        "codigos": {"127.0.0.2": "Infecção detectada (botnet/worm/proxy aberto)"},
    },
}

TOR_DNSEL = "dnsel.torproject.org"

RIPESTAT_BASE = "https://stat.ripe.net/data"

# --------------------------------------------------------------------------
# Utilitários de saída
# --------------------------------------------------------------------------


def cor(texto, codigo):
    return f"\033[{codigo}m{texto}\033[0m"


def titulo(texto):
    print("\n" + cor(f"┌─ {texto} " + "─" * max(0, 58 - len(texto)), "1;36"))


def subtitulo(texto):
    print(cor(f"│ {texto}", "0;36"))


def campo(nome, valor, alerta=False, nota=None, indent=2):
    if valor in (None, "", [], {}):
        valor = "-"
    cor_valor = "1;31" if alerta else "0"
    largura = max(10, 30 - indent)  # mantém a coluna dos ":" alinhada
    linha = f"{' ' * indent}{nome:<{largura}}: {cor(valor, cor_valor)}"
    if nota:
        linha += cor(f"  [{nota}]", "0;90")
    print(linha)


def normalizar(s):
    if s is None:
        return ""
    s = unicodedata.normalize("NFKD", str(s)).encode("ASCII", "ignore").decode("ASCII")
    return " ".join(s.lower().split())


def validar_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def http_get_json(url, headers=None, timeout=TIMEOUT):
    """Retorna (dados, erro, tempo_ms)."""
    inicio = time.time()
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "ip-investigate/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            corpo = json.loads(resp.read().decode("utf-8", errors="replace"))
            ms = int((time.time() - inicio) * 1000)
            if not isinstance(corpo, dict):
                return None, f"Resposta inesperada: {corpo}", ms
            return corpo, None, ms
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.reason}", int((time.time() - inicio) * 1000)
    except urllib.error.URLError as e:
        return None, f"Rede: {e.reason}", int((time.time() - inicio) * 1000)
    except json.JSONDecodeError:
        return None, "JSON inválido", int((time.time() - inicio) * 1000)
    except Exception as e:
        return None, f"Erro: {e}", int((time.time() - inicio) * 1000)


# --------------------------------------------------------------------------
# Propriedades intrínsecas do endereço (sem rede)
# --------------------------------------------------------------------------


def propriedades_endereco(ip):
    obj = ipaddress.ip_address(ip)
    inteiro = int(obj)

    props = {
        "versao": f"IPv{obj.version}",
        "inteiro": inteiro,
        "hex": hex(inteiro),
        "reverso_arpa": obj.reverse_pointer,
        "is_global": obj.is_global,
        "is_private": obj.is_private,
        "is_reserved": obj.is_reserved,
        "is_multicast": obj.is_multicast,
        "is_loopback": obj.is_loopback,
        "is_link_local": obj.is_link_local,
        "is_unspecified": obj.is_unspecified,
    }

    if obj.version == 4:
        octetos = [int(o) for o in ip.split(".")]
        props["binario"] = ".".join(f"{o:08b}" for o in octetos)
        props["rede_24"] = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        props["rede_16"] = str(ipaddress.ip_network(f"{ip}/16", strict=False))
        primeiro = octetos[0]
        if primeiro < 128:
            props["classe_legado"] = "A"
        elif primeiro < 192:
            props["classe_legado"] = "B"
        elif primeiro < 224:
            props["classe_legado"] = "C"
        elif primeiro < 240:
            props["classe_legado"] = "D (multicast)"
        else:
            props["classe_legado"] = "E (reservado)"
    else:
        props["comprimido"] = obj.compressed
        props["expandido"] = obj.exploded

    return props


# --------------------------------------------------------------------------
# Fontes: geolocalização
# --------------------------------------------------------------------------


def consultar_ipapi_is(ip):
    data, err, ms = http_get_json(f"https://api.ipapi.is/?q={ip}")
    return {"erro": err, "_ms": ms} if err else {**data, "_ms": ms}


def consultar_ip_api_com(ip):
    campos = ("status,message,continent,country,countryCode,region,regionName,city,district,"
              "zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
    data, err, ms = http_get_json(f"http://ip-api.com/json/{ip}?fields={campos}")
    if err:
        return {"erro": err, "_ms": ms}
    if data.get("status") == "fail":
        return {"erro": data.get("message", "falha"), "_ms": ms}
    return {**data, "_ms": ms}


def consultar_ipwho_is(ip):
    data, err, ms = http_get_json(f"https://ipwho.is/{ip}")
    if err:
        return {"erro": err, "_ms": ms}
    if data.get("success") is False:
        return {"erro": data.get("message", "falha"), "_ms": ms}
    return {**data, "_ms": ms}


# --------------------------------------------------------------------------
# Fontes: registro e roteamento
# --------------------------------------------------------------------------


def consultar_rdap(ip):
    data, err, ms = http_get_json(f"https://rdap.org/ip/{ip}")
    return {"erro": err, "_ms": ms} if err else {**data, "_ms": ms}


def _ripestat(endpoint, resource):
    data, err, ms = http_get_json(f"{RIPESTAT_BASE}/{endpoint}/data.json?resource={resource}")
    if err:
        return {"erro": err, "_ms": ms}
    return {**(data.get("data") or {}), "_ms": ms}


def consultar_ripestat_network(ip):
    """Prefixo anunciado e ASNs de origem."""
    return _ripestat("network-info", ip)


def consultar_ripestat_abuse(ip):
    """Contatos de abuse autoritativos + RIR responsável."""
    return _ripestat("abuse-contact-finder", ip)


def consultar_ripestat_routing(ip):
    """Status de roteamento BGP: visibilidade, primeira vez visto."""
    return _ripestat("routing-status", ip)


def consultar_ripestat_blocklist(ip):
    """Histórico de presença em blocklists conhecidas pelo RIPE."""
    return _ripestat("blocklist", ip)


def consultar_ripestat_as_overview(asn):
    """Overview do AS: holder, tipo, bloco de alocação, se está anunciado."""
    if not asn:
        return {"erro": "ASN não determinado"}
    return _ripestat("as-overview", f"AS{asn}")


def consultar_ripestat_rpki(asn, prefixo):
    """Validação RPKI (Route Origin Authorization) do par ASN/prefixo."""
    if not asn or not prefixo:
        return {"erro": "ASN ou prefixo não determinado"}
    data, err, ms = http_get_json(
        f"{RIPESTAT_BASE}/rpki-validation/data.json?resource=AS{asn}&prefix={prefixo}")
    if err:
        return {"erro": err, "_ms": ms}
    return {**(data.get("data") or {}), "_ms": ms}


# --------------------------------------------------------------------------
# Fontes: DNS
# --------------------------------------------------------------------------


def reverse_dns(ip):
    """PTR + validação FCrDNS (forward-confirmed reverse DNS)."""
    resultado = {"ptr": None, "fcrdns": None, "ips_do_ptr": [], "erro": None}
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        resultado["ptr"] = ptr
    except (socket.herror, socket.gaierror):
        resultado["erro"] = "Nenhum registro PTR"
        return resultado
    except Exception as e:
        resultado["erro"] = str(e)
        return resultado

    # FCrDNS: o hostname do PTR resolve de volta para este mesmo IP?
    try:
        _, _, ips = socket.gethostbyname_ex(resultado["ptr"])
        resultado["ips_do_ptr"] = ips
        resultado["fcrdns"] = ip in ips
    except Exception:
        resultado["fcrdns"] = False

    return resultado


def checar_dnsbl(ip, dnsbl_host, info):
    """Consulta DNSBL e traduz o código de retorno."""
    try:
        partes = ip.split(".")
        if len(partes) != 4:
            return dnsbl_host, {"listado": None, "motivo": "IPv6 não suportado nesta lista"}
        query = ".".join(reversed(partes)) + "." + dnsbl_host
        _, _, codigos = socket.gethostbyname_ex(query)

        motivos = []
        for c in codigos:
            motivos.append(info["codigos"].get(c, f"código {c} (não mapeado)"))

        return dnsbl_host, {
            "listado": True,
            "codigos": codigos,
            "motivo": "; ".join(motivos),
            "descricao": info["descricao"],
        }
    except socket.gaierror:
        return dnsbl_host, {"listado": False, "descricao": info["descricao"]}
    except Exception as e:
        return dnsbl_host, {"listado": None, "motivo": str(e)}


def checar_todas_dnsbl(ip):
    resultados = {}
    with ThreadPoolExecutor(max_workers=len(DNSBL_LIST)) as ex:
        futs = [ex.submit(checar_dnsbl, ip, host, info) for host, info in DNSBL_LIST.items()]
        for fut in futs:
            host, dados = fut.result()
            resultados[host] = dados
    return resultados


def checar_tor_exit(ip):
    """Consulta a DNSEL oficial do Tor Project."""
    try:
        partes = ip.split(".")
        if len(partes) != 4:
            return {"exit_node": None, "obs": "IPv6 não suportado"}
        query = ".".join(reversed(partes)) + ".80." + ".".join(reversed(partes)) + "." + TOR_DNSEL
        socket.gethostbyname(query)
        return {"exit_node": True}
    except socket.gaierror:
        return {"exit_node": False}
    except Exception as e:
        return {"exit_node": None, "obs": str(e)}


# --------------------------------------------------------------------------
# Consolidação
# --------------------------------------------------------------------------


def _ok(d):
    return d if isinstance(d, dict) and "erro" not in d else {}


def _sub(d, chave):
    v = d.get(chave)
    return v if isinstance(v, dict) else {}


def resolver_consenso(candidatos):
    """candidatos: [(valor, fonte)]. Retorna (valor, [concordam], [(valor,fonte) divergentes])."""
    validos = [(v, f) for v, f in candidatos if v not in (None, "", [], {})]
    if not validos:
        return None, [], []
    contagem = Counter(normalizar(v) for v, _ in validos)
    vencedor = contagem.most_common(1)[0][0]
    escolhido = next(v for v, _ in validos if normalizar(v) == vencedor)
    concordam = [f for v, f in validos if normalizar(v) == vencedor]
    divergem = [(v, f) for v, f in validos if normalizar(v) != vencedor]
    return escolhido, concordam, divergem


def consolidar(ip, b):
    ipapi = _ok(b["ipapi_is"])
    ipapicom = _ok(b["ip_api_com"])
    ipwho = _ok(b["ipwho_is"])
    rdap = _ok(b["rdap"])

    loc = _sub(ipapi, "location")
    asn_ipapi = _sub(ipapi, "asn")
    comp = _sub(ipapi, "company")
    conn = _sub(ipwho, "connection")
    seg = _sub(ipwho, "security")
    tz_w = ipwho.get("timezone")
    tz_w = tz_w.get("id") if isinstance(tz_w, dict) else tz_w

    pais = resolver_consenso([
        (f"{loc.get('country')} ({loc.get('country_code')})" if loc.get("country") else None, "ipapi.is"),
        (f"{ipapicom.get('country')} ({ipapicom.get('countryCode')})" if ipapicom.get("country") else None, "ip-api.com"),
        (f"{ipwho.get('country')} ({ipwho.get('country_code')})" if ipwho.get("country") else None, "ipwho.is"),
    ])
    if pais[0] is None and rdap.get("country"):
        pais = (rdap["country"], ["RDAP"], [])

    cidade = resolver_consenso([
        (f"{loc.get('city')} / {loc.get('state')}" if loc.get("city") else None, "ipapi.is"),
        (f"{ipapicom.get('city')} / {ipapicom.get('regionName')}" if ipapicom.get("city") else None, "ip-api.com"),
        (f"{ipwho.get('city')} / {ipwho.get('region')}" if ipwho.get("city") else None, "ipwho.is"),
    ])

    timezone = resolver_consenso([
        (loc.get("timezone"), "ipapi.is"),
        (ipapicom.get("timezone"), "ip-api.com"),
        (tz_w, "ipwho.is"),
    ])

    def cfmt(lat, lon):
        if lat is None or lon is None:
            return None
        try:
            return f"{float(lat):.4f}, {float(lon):.4f}"
        except (TypeError, ValueError):
            return None

    coord_cands = [(v, f) for v, f in (
        (cfmt(loc.get("latitude"), loc.get("longitude")), "ipapi.is"),
        (cfmt(ipapicom.get("lat"), ipapicom.get("lon")), "ip-api.com"),
        (cfmt(ipwho.get("latitude"), ipwho.get("longitude")), "ipwho.is"),
    ) if v]
    if coord_cands:
        def prox(v):
            la, lo = v.split(", ")
            return f"{float(la):.1f},{float(lo):.1f}"
        cnt = Counter(prox(v) for v, _ in coord_cands)
        venc = cnt.most_common(1)[0][0]
        coord = (next(v for v, _ in coord_cands if prox(v) == venc),
                 [f for v, f in coord_cands if prox(v) == venc],
                 [(v, f) for v, f in coord_cands if prox(v) != venc])
    else:
        coord = (None, [], [])

    raw_as = ipapicom.get("as") or ""
    asn_com = raw_as.split()[0].replace("AS", "") if raw_as else None
    ripe_net = _ok(b["ripe_network"])
    asns_ripe = ripe_net.get("asns") or []
    asn_ripe = str(asns_ripe[0]) if asns_ripe else None

    asn_num = resolver_consenso([
        (str(asn_ipapi.get("asn")) if asn_ipapi.get("asn") else None, "ipapi.is"),
        (asn_com, "ip-api.com"),
        (str(conn.get("asn")) if conn.get("asn") else None, "ipwho.is"),
        (asn_ripe, "RIPEstat"),
    ])

    operadora = resolver_consenso([
        (comp.get("name") or ipapi.get("org"), "ipapi.is"),
        (ipapicom.get("isp"), "ip-api.com"),
        (conn.get("isp") or conn.get("org"), "ipwho.is"),
    ])

    prefixo = resolver_consenso([
        (asn_ipapi.get("route"), "ipapi.is"),
        (ripe_net.get("prefix"), "RIPEstat"),
        (rdap.get("handle") if rdap.get("handle", "").count("/") else None, "RDAP"),
    ])

    def flag(cands):
        acusaram = [f for v, f in cands if v]
        return bool(acusaram), acusaram

    return {
        "ip": ip,
        "propriedades": b["propriedades"],
        "pais": pais,
        "cidade": cidade,
        "timezone": timezone,
        "coordenadas": coord,
        "continente": ipapicom.get("continent") or ipwho.get("continent"),
        "cep": ipapicom.get("zip") or ipwho.get("postal"),
        "distrito": ipapicom.get("district"),
        "utc_offset": ipapicom.get("offset"),
        "asn_num": asn_num,
        "asn_tipo": asn_ipapi.get("type"),
        "asn_descr": asn_ipapi.get("descr") or ipapicom.get("asname"),
        "asn_dominio": asn_ipapi.get("domain") or conn.get("domain"),
        "asn_abuse": asn_ipapi.get("abuse") or comp.get("abuse"),
        "rir": ipapi.get("rir") or _ok(b["ripe_abuse"]).get("authoritative_rir"),
        "operadora": operadora,
        "prefixo": prefixo,
        "org_ipapi_tipo": comp.get("type"),
        "datacenter": _sub(ipapi, "datacenter").get("datacenter"),
        "rdap": rdap,
        "ripe_network": ripe_net,
        "ripe_abuse": _ok(b["ripe_abuse"]),
        "ripe_routing": _ok(b["ripe_routing"]),
        "ripe_blocklist": _ok(b["ripe_blocklist"]),
        "ripe_as": _ok(b["ripe_as"]),
        "ripe_rpki": _ok(b["ripe_rpki"]),
        "dns": b["dns"],
        "dnsbl": b["dnsbl"],
        "tor": b["tor"],
        "is_datacenter": flag([(ipapi.get("is_datacenter"), "ipapi.is"), (ipapicom.get("hosting"), "ip-api.com")]),
        "is_vpn": flag([(ipapi.get("is_vpn"), "ipapi.is"), (seg.get("vpn"), "ipwho.is")]),
        "is_proxy": flag([(ipapi.get("is_proxy"), "ipapi.is"), (ipapicom.get("proxy"), "ip-api.com"), (seg.get("proxy"), "ipwho.is")]),
        "is_tor": flag([(ipapi.get("is_tor"), "ipapi.is"), (seg.get("tor"), "ipwho.is"), (b["tor"].get("exit_node"), "Tor DNSEL")]),
        "is_mobile": flag([(ipapi.get("is_mobile"), "ipapi.is"), (ipapicom.get("mobile"), "ip-api.com")]),
        "is_abuser": flag([(ipapi.get("is_abuser"), "ipapi.is")]),
        "is_crawler": flag([(ipapi.get("is_crawler"), "ipapi.is")]),
        "is_satellite": flag([(ipapi.get("is_satellite"), "ipapi.is")]),
        "is_bogon": flag([(ipapi.get("is_bogon"), "ipapi.is")]),
        "tempos": {n: b[k].get("_ms") for n, k in (
            ("ipapi.is", "ipapi_is"), ("ip-api.com", "ip_api_com"), ("ipwho.is", "ipwho_is"),
            ("RDAP", "rdap"), ("RIPEstat/network", "ripe_network"),
        ) if isinstance(b[k], dict)},
        "erros": {n: b[k].get("erro") for n, k in (
            ("ipapi.is", "ipapi_is"), ("ip-api.com", "ip_api_com"), ("ipwho.is", "ipwho_is"),
            ("RDAP", "rdap"), ("RIPEstat/network", "ripe_network"),
            ("RIPEstat/abuse", "ripe_abuse"), ("RIPEstat/routing", "ripe_routing"),
            ("RIPEstat/blocklist", "ripe_blocklist"), ("RIPEstat/AS", "ripe_as"),
            ("RIPEstat/RPKI", "ripe_rpki"),
        ) if isinstance(b[k], dict) and b[k].get("erro")},
    }


# --------------------------------------------------------------------------
# Relatório
# --------------------------------------------------------------------------


def mostrar_consenso(nome, resolvido, alerta=False):
    valor, concordam, divergem = resolvido
    nota = None
    if valor is not None:
        if divergem:
            outros = "; ".join(f"{f}={v}" for v, f in divergem)
            nota = f"{len(concordam)}/{len(concordam)+len(divergem)} · divergem: {outros}"
        elif len(concordam) > 1:
            nota = f"{len(concordam)} fontes"
        elif concordam:
            nota = concordam[0]
    campo(nome, valor, alerta=alerta or bool(divergem), nota=nota)


def exibir_relatorio(c):
    p = c["propriedades"]

    # ---------------- Endereço ----------------
    titulo("PROPRIEDADES DO ENDEREÇO")
    campo("IP", c["ip"])
    campo("Versão", p["versao"])
    campo("Inteiro (decimal)", p["inteiro"])
    campo("Hexadecimal", p["hex"])
    if "binario" in p:
        campo("Binário", p["binario"])
        campo("Classe (legado)", p["classe_legado"])
        campo("Rede /24", p["rede_24"])
        campo("Rede /16", p["rede_16"])
    campo("Ponteiro in-addr.arpa", p["reverso_arpa"])
    escopos = [k.replace("is_", "").replace("_", "-") for k in
               ("is_private", "is_reserved", "is_multicast", "is_loopback", "is_link_local")
               if p.get(k)]
    campo("Escopo", ", ".join(escopos) if escopos else "global (roteável)",
          alerta=bool(escopos))
    campo("Bogon (ipapi.is)", "SIM" if c["is_bogon"][0] else "Não", alerta=c["is_bogon"][0])

    # ---------------- Geo ----------------
    titulo("GEOLOCALIZAÇÃO")
    mostrar_consenso("País", c["pais"])
    mostrar_consenso("Cidade / Região", c["cidade"])
    campo("Distrito", c["distrito"])
    campo("Continente", c["continente"])
    campo("CEP / Postal", c["cep"])
    mostrar_consenso("Timezone", c["timezone"])
    campo("Offset UTC (s)", c["utc_offset"])
    mostrar_consenso("Coordenadas", c["coordenadas"])

    # ---------------- ASN ----------------
    titulo("SISTEMA AUTÔNOMO (ASN)")
    asn_v = c["asn_num"][0]
    mostrar_consenso("ASN", (f"AS{asn_v}" if asn_v else None, c["asn_num"][1], c["asn_num"][2]))
    mostrar_consenso("Operadora / ISP", c["operadora"])
    campo("Descrição do AS", c["asn_descr"])
    campo("Tipo de AS", c["asn_tipo"], nota="ipapi.is" if c["asn_tipo"] else None)
    campo("Domínio do AS", c["asn_dominio"])
    campo("Contato de abuse (AS)", c["asn_abuse"])
    campo("RIR autoritativo", c["rir"])

    ras = c["ripe_as"]
    if ras:
        campo("Holder (RIPEstat)", ras.get("holder"), nota="RIPEstat")
        campo("AS anunciado em BGP", "Sim" if ras.get("announced") else "Não", nota="RIPEstat")
        bloco_as = ras.get("block") or {}
        if isinstance(bloco_as, dict) and bloco_as:
            campo("Bloco de alocação do AS", f"{bloco_as.get('resource')} ({bloco_as.get('name')})", nota="RIPEstat")

    # ---------------- Roteamento ----------------
    titulo("ROTEAMENTO / BGP")
    mostrar_consenso("Prefixo anunciado", c["prefixo"])

    rnet = c["ripe_network"]
    if rnet:
        asns = rnet.get("asns") or []
        campo("ASNs de origem", ", ".join(f"AS{a}" for a in asns) if asns else None, nota="RIPEstat")

    rrout = c["ripe_routing"]
    if rrout:
        vis = rrout.get("visibility") or {}
        if isinstance(vis, dict):
            v4 = vis.get("v4") or {}
            if isinstance(v4, dict) and v4:
                campo("Visibilidade BGP (IPv4)",
                      f"{v4.get('ris_peers_seeing')} de {v4.get('total_ris_peers')} peers RIS",
                      nota="RIPEstat")
        campo("Primeira vez visto (BGP)", rrout.get("first_seen", {}).get("time")
              if isinstance(rrout.get("first_seen"), dict) else None, nota="RIPEstat")
        campo("Última vez visto (BGP)", rrout.get("last_seen", {}).get("time")
              if isinstance(rrout.get("last_seen"), dict) else None, nota="RIPEstat")
        origens = rrout.get("origins") or []
        if origens:
            desc = ", ".join(f"AS{o.get('origin')}" for o in origens if isinstance(o, dict))
            campo("Origens observadas", desc, nota="RIPEstat")

    rpki = c["ripe_rpki"]
    if rpki:
        status = rpki.get("status")
        alerta_rpki = status in ("invalid", "invalid_asn", "invalid_length")
        campo("Validação RPKI", status, alerta=alerta_rpki, nota="RIPEstat")
        rota_valida = rpki.get("validating_roas") or []
        for roa in rota_valida[:3]:
            if isinstance(roa, dict):
                campo("  ROA", f"AS{roa.get('origin')} {roa.get('prefix')} maxLen={roa.get('max_length')} [{roa.get('validity')}]",
                      indent=4)

    # ---------------- Registro / WHOIS ----------------
    titulo("REGISTRO (RDAP / WHOIS)")
    rd = c["rdap"]
    if rd:
        campo("Handle do bloco", rd.get("handle"))
        campo("Nome do objeto", rd.get("name"))
        if rd.get("startAddress") and rd.get("endAddress"):
            campo("Faixa alocada", f"{rd['startAddress']} - {rd['endAddress']}")
        campo("Tipo de alocação", rd.get("type"))
        campo("País (registro)", rd.get("country"))
        campo("Versão IP", rd.get("ipVersion"))
        status = rd.get("status") or []
        campo("Status do objeto", ", ".join(status) if status else None)

        # Datas de registro
        for ev in (rd.get("events") or []):
            if not isinstance(ev, dict):
                continue
            acao = ev.get("eventAction", "")
            if acao in ("registration", "last changed", "last modified"):
                campo(f"Evento: {acao}", ev.get("eventDate"))

        # Entidades, papéis e contatos
        entidades = rd.get("entities") or []
        if entidades:
            print(cor("\n  Entidades registradas:", "0;36"))
        for e in entidades:
            if not isinstance(e, dict):
                continue
            papeis = ", ".join(e.get("roles") or []) or "?"
            nome = None
            emails = []
            telefones = []
            vcard = e.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if not (isinstance(item, list) and len(item) > 3):
                        continue
                    if item[0] == "fn":
                        nome = item[3]
                    elif item[0] == "email":
                        emails.append(item[3])
                    elif item[0] == "tel":
                        telefones.append(item[3])
            detalhe = nome or e.get("handle") or "?"
            campo(f"[{papeis}]", detalhe, indent=4)
            if emails:
                campo("  e-mail", ", ".join(emails), indent=6)
            if telefones:
                campo("  telefone", ", ".join(telefones), indent=6)

        # Remarks (avisos do registro)
        for rm in (rd.get("remarks") or []):
            if isinstance(rm, dict) and rm.get("description"):
                texto = " ".join(str(d) for d in rm["description"])[:200]
                campo("Observação", texto, indent=4)
    else:
        campo("RDAP", "indisponível", alerta=True)

    rab = c["ripe_abuse"]
    if rab:
        contatos = rab.get("abuse_contacts") or []
        campo("Abuse (RIPEstat)", ", ".join(contatos) if contatos else None, nota="RIPEstat")

    # ---------------- DNS ----------------
    titulo("DNS")
    dns = c["dns"]
    campo("Registro PTR", dns.get("ptr") or dns.get("erro"))
    if dns.get("ptr"):
        fc = dns.get("fcrdns")
        campo("FCrDNS válido", "Sim" if fc else "NÃO", alerta=(fc is False),
              nota="PTR resolve de volta para o IP" if fc else "PTR não confirma o IP (comum em residencial/spoofing)")
        if dns.get("ips_do_ptr"):
            campo("IPs do hostname PTR", ", ".join(dns["ips_do_ptr"]), indent=4)

    # ---------------- Classificação ----------------
    titulo("CLASSIFICAÇÃO DE INFRAESTRUTURA")
    for rotulo, chave in (
        ("Datacenter / Hosting", "is_datacenter"),
        ("VPN", "is_vpn"),
        ("Proxy", "is_proxy"),
        ("Tor (exit node)", "is_tor"),
        ("Rede móvel", "is_mobile"),
        ("Crawler / bot conhecido", "is_crawler"),
        ("Satélite", "is_satellite"),
        ("Marcado como abuser", "is_abuser"),
    ):
        valor, fontes = c[chave]
        campo(rotulo, "SIM" if valor else "Não", alerta=valor,
              nota=", ".join(fontes) if fontes else None)
    if c["datacenter"]:
        campo("Datacenter identificado", c["datacenter"], nota="ipapi.is")
    if c["org_ipapi_tipo"]:
        campo("Tipo de organização", c["org_ipapi_tipo"], nota="ipapi.is")

    # ---------------- Blacklists ----------------
    titulo("BLACKLISTS DNS (DNSBL)")
    for host, dados in c["dnsbl"].items():
        listado = dados.get("listado")
        if listado is True:
            codigos = ", ".join(dados.get("codigos", []))
            campo(host, f"LISTADO ({codigos})", alerta=True)
            campo("  motivo", dados.get("motivo"), indent=4)
            campo("  lista", dados.get("descricao"), indent=4)
        elif listado is False:
            campo(host, "não listado", nota=dados.get("descricao"))
        else:
            campo(host, f"indeterminado - {dados.get('motivo', '')}")

    tor = c["tor"]
    if tor.get("exit_node") is True:
        campo("Tor DNSEL", "EXIT NODE CONFIRMADO", alerta=True)
    elif tor.get("exit_node") is False:
        campo("Tor DNSEL", "não é exit node")
    else:
        campo("Tor DNSEL", f"indeterminado {tor.get('obs', '')}")

    rbl = c["ripe_blocklist"]
    if rbl and rbl.get("sources"):
        print(cor("\n  Histórico de blocklists (RIPEstat):", "0;36"))
        fontes_rbl = rbl.get("sources") or {}
        if isinstance(fontes_rbl, dict):
            for nome_lista, entradas in list(fontes_rbl.items())[:5]:
                if isinstance(entradas, list) and entradas:
                    ultima = entradas[-1]
                    detalhe = ultima.get("details", "") if isinstance(ultima, dict) else ""
                    campo(nome_lista, f"{len(entradas)} registro(s) · último: {detalhe}",
                          alerta=True, indent=4)

    # ---------------- Diagnóstico da coleta ----------------
    titulo("DIAGNÓSTICO DA COLETA")
    tempos = ", ".join(f"{n}={ms}ms" for n, ms in c["tempos"].items() if ms is not None)
    campo("Latência das fontes", tempos or None)
    if c["erros"]:
        for nome, err in c["erros"].items():
            campo(f"Falha: {nome}", err, alerta=True)
    else:
        campo("Falhas", "nenhuma")
    print()


def exibir_detalhado(brutos):
    titulo("RESPOSTA CRUA DE CADA FONTE")
    for nome, chave in (
        ("ipapi.is", "ipapi_is"), ("ip-api.com", "ip_api_com"), ("ipwho.is", "ipwho_is"),
        ("RDAP", "rdap"), ("RIPEstat/network-info", "ripe_network"),
        ("RIPEstat/abuse-contact", "ripe_abuse"), ("RIPEstat/routing-status", "ripe_routing"),
        ("RIPEstat/blocklist", "ripe_blocklist"), ("RIPEstat/as-overview", "ripe_as"),
        ("RIPEstat/rpki-validation", "ripe_rpki"), ("DNS", "dns"), ("DNSBL", "dnsbl"), ("Tor", "tor"),
    ):
        print(cor(f"\n  ── {nome} ──", "1;36"))
        texto = json.dumps(brutos.get(chave), indent=2, ensure_ascii=False, default=str)
        print("  " + texto.replace("\n", "\n  "))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def investigar(ip, detalhado=False, saida_json=False):
    if not saida_json:
        print(cor(f"\n{'═' * 62}", "1;35"))
        print(cor(f"  DOSSIÊ TÉCNICO DE IP: {ip}", "1;35"))
        print(cor(f"  {time.strftime('%Y-%m-%d %H:%M:%S %Z')}", "0;90"))
        print(cor(f"{'═' * 62}", "1;35"))
        print(cor("\n  Consultando fontes...", "0;90"), end="", flush=True)

    brutos = {"propriedades": propriedades_endereco(ip)}

    # Rodada 1: tudo que não depende de ASN/prefixo
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {
            "ipapi_is": ex.submit(consultar_ipapi_is, ip),
            "ip_api_com": ex.submit(consultar_ip_api_com, ip),
            "ipwho_is": ex.submit(consultar_ipwho_is, ip),
            "rdap": ex.submit(consultar_rdap, ip),
            "ripe_network": ex.submit(consultar_ripestat_network, ip),
            "ripe_abuse": ex.submit(consultar_ripestat_abuse, ip),
            "ripe_routing": ex.submit(consultar_ripestat_routing, ip),
            "ripe_blocklist": ex.submit(consultar_ripestat_blocklist, ip),
            "dns": ex.submit(reverse_dns, ip),
            "dnsbl": ex.submit(checar_todas_dnsbl, ip),
            "tor": ex.submit(checar_tor_exit, ip),
        }
        for k, f in futs.items():
            brutos[k] = f.result()

    # Rodada 2: consultas que dependem do ASN/prefixo descobertos acima
    rnet = _ok(brutos["ripe_network"])
    asns = rnet.get("asns") or []
    asn_desc = str(asns[0]) if asns else None
    if not asn_desc:
        ia = _ok(brutos["ipapi_is"])
        asn_desc = str(_sub(ia, "asn").get("asn") or "") or None
    prefixo_desc = rnet.get("prefix") or _sub(_ok(brutos["ipapi_is"]), "asn").get("route")

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_as = ex.submit(consultar_ripestat_as_overview, asn_desc)
        f_rpki = ex.submit(consultar_ripestat_rpki, asn_desc, prefixo_desc)
        brutos["ripe_as"] = f_as.result()
        brutos["ripe_rpki"] = f_rpki.result()

    if not saida_json:
        print("\r" + " " * 30 + "\r", end="")

    consolidado = consolidar(ip, brutos)

    if saida_json:
        print(json.dumps(consolidado, indent=2, ensure_ascii=False, default=str))
        return

    exibir_relatorio(consolidado)
    if detalhado:
        exibir_detalhado(brutos)


def pausar_no_windows():
    if platform.system() == "Windows":
        input("\nPressione ENTER para fechar...")


def main():
    try:
        flags = [a for a in sys.argv[1:] if a.startswith("--")]
        args = [a for a in sys.argv[1:] if not a.startswith("--")]
        detalhado = "--detalhado" in flags
        saida_json = "--json" in flags

        ip = args[0].strip() if args else input("Digite o IP público a investigar: ").strip()

        if not validar_ip(ip):
            print(cor(f"IP inválido: '{ip}'", "1;31"))
            pausar_no_windows()
            sys.exit(1)

        investigar(ip, detalhado=detalhado, saida_json=saida_json)

    except KeyboardInterrupt:
        print(cor("\nInterrompido pelo usuário.", "0;90"))
    except Exception as e:
        print(cor(f"\nOcorreu um erro inesperado: {e}", "1;31"))
        import traceback
        traceback.print_exc()
    finally:
        if not any(a == "--json" for a in sys.argv[1:]):
            pausar_no_windows()


if __name__ == "__main__":
    main()
