#!/usr/bin/env python3
"""
vpn-split — mantém cada VPN apenas nas redes que lhe pertencem.

Modelo:
  * a tabela `main` é a fonte da verdade: toda rede interna de VPN vira rota
    específica (nunca default);
  * rotas default-like instaladas por clientes (0.0.0.0/1, 128.0.0.0/1) são
    removidas — só a Mullvad pode ser saída de internet;
  * as redes internas + endpoints + Docker + LAN + IPs da faculdade entram num
    set nft na tabela da Mullvad com mark/accept, furando o kill-switch sem
    tirar o tráfego do túnel;
  * DNS split por domínio de roteamento no systemd-resolved.

Uso: vpn-split [apply|status|clear|watch] [--dry-run]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import select
import subprocess
import sys
import time
import tomllib
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("VPN_SPLIT_CONFIG", "/etc/vpn-split/config.toml"))
STATE_DIR = Path("/run/vpn-split")
STATE_PATH = STATE_DIR / "state.json"
FALLBACK_FLAG = Path("/etc/vpn-split/fallback")
NFT_SET = "vpn_split_v4"
NFT_COMMENT = "vpn-split-exclude"
DEFAULT_TABLE = "inet mullvad"

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")


# --------------------------------------------------------------------------- #
# util
# --------------------------------------------------------------------------- #
def log(msg: str, level: str = "INFO") -> None:
    print(f"[vpn-split] {level:<5} {msg}", flush=True)


def run(cmd: list[str], *, ns: str | None = None, stdin: str | None = None,
        check: bool = False) -> subprocess.CompletedProcess:
    if ns:
        cmd = ["ip", "netns", "exec", ns, *cmd]
    p = subprocess.run(cmd, text=True, capture_output=True, input=stdin)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {p.stderr.strip()}")
    return p


def ok(cmd: list[str], *, ns: str | None = None) -> bool:
    return run(cmd, ns=ns).returncode == 0


def out(cmd: list[str], *, ns: str | None = None) -> str:
    return run(cmd, ns=ns).stdout


def ipj(*args: str, ns: str | None = None) -> list[dict]:
    txt = out(["ip", "-j", *args], ns=ns).strip()
    return json.loads(txt) if txt else []


def dry(cmd: list[str], *, dry_run: bool, ns: str | None = None,
        stdin: str | None = None) -> bool:
    pretty = " ".join(cmd)
    if ns:
        pretty = f"ip netns exec {ns} {pretty}"
    if dry_run:
        log(f"DRY {pretty}")
        return True
    p = run(cmd, ns=ns, stdin=stdin)
    if p.returncode != 0:
        log(f"falhou: {pretty} :: {p.stderr.strip()}", "WARN")
    return p.returncode == 0


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise SystemExit(f"config não encontrada: {CONFIG_PATH}")
    with CONFIG_PATH.open("rb") as f:
        cfg = tomllib.load(f)
    cfg.setdefault("general", {})
    cfg.setdefault("domains", {})
    cfg.setdefault("networks", {})
    cfg.setdefault("priority", {})
    cfg.setdefault("exclude", {})
    cfg.setdefault("endpoints", {})
    cfg.setdefault("mullvad", {})
    cfg.setdefault("netns", {})
    cfg.setdefault("vpn", {})
    cfg.setdefault("profiles", {})
    return cfg


def read_domain_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    res = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            res.append(line.split()[0])
    return res


# --------------------------------------------------------------------------- #
# descoberta
# --------------------------------------------------------------------------- #
def default_route(iface: str | None = None) -> dict | None:
    for r in ipj("route", "show", "default"):
        if iface is None or r.get("dev") == iface:
            return r
    return None


def resolvectl_dns(iface: str) -> list[str]:
    txt = out(["resolvectl", "dns", iface])
    part = txt.split(":", 1)[1] if ":" in txt else ""
    return [t for t in part.split() if IPV4_RE.match(t)]


def resolvectl_domains(iface: str) -> list[str]:
    txt = out(["resolvectl", "domain", iface])
    part = txt.split(":", 1)[1] if ":" in txt else ""
    return part.split()


def link_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def wg_ifaces(exclude: set[str]) -> list[str]:
    res = []
    for i in out(["wg", "show", "interfaces"]).split():
        if i in exclude or "mullvad" in i:
            continue
        # wtN é o NetBird (kernel WireGuard) — não tratar como wg dedicado
        if re.match(r"^(wt|nb)\d+$", i):
            continue
        res.append(i)
    return res


def tunnel_ifaces(pattern: str, exclude: set[str]) -> list[str]:
    res = []
    for p in Path("/sys/class/net").iterdir():
        if re.match(pattern, p.name) and p.name not in exclude:
            res.append(p.name)
    return res


def iface_subnets(iface: str, ns: str | None = None) -> list[str]:
    res = []
    for link in ipj("addr", "show", "dev", iface, ns=ns):
        for ai in link.get("addr_info", []):
            if ai.get("family") == "inet" and ai.get("prefixlen", 32) < 32:
                import ipaddress
                net = ipaddress.ip_interface(f"{ai['local']}/{ai['prefixlen']}").network
                res.append(str(net))
    return res


def route_prefixes(iface: str, routes: list[dict]) -> list[tuple[str, str | None, str]]:
    """(prefixo, gateway, dev) das rotas que apontam para a interface."""
    res = []
    for r in routes:
        if r.get("dev") != iface:
            continue
        dst = r.get("dst")
        if not dst or dst == "default" or r.get("type") == "unreachable":
            continue
        if dst in ("0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0"):
            continue
        if r.get("scope") == "host":
            continue
        res.append((dst, r.get("gateway"), iface))
    return res


def table_routes(table: str, ns: str | None = None) -> list[dict]:
    if not ok(["ip", "route", "show", "table", table], ns=ns):
        return []
    return ipj("route", "show", "table", table, ns=ns)


# --------------------------------------------------------------------------- #
# fontes
# --------------------------------------------------------------------------- #
class Source:
    def __init__(self, name: str, iface: str, priority: int, kind: str,
                 ns: str | None = None, via: str | None = None):
        self.name = name
        self.iface = iface
        self.priority = priority
        self.kind = kind          # wg | netbird | pritunl | netns | static
        self.ns = ns
        self.via = via
        self.prefixes: list[tuple[str, str | None, str]] = []


# --------------------------------------------------------------------------- #
# registro de serviços de VPN
# --------------------------------------------------------------------------- #
DEFAULT_VPN_REGISTRY: list[dict] = [
    {"name": "mullvad", "type": "mullvad", "iface": "wg0-mullvad",
     "priority": 5, "routes": [], "manual": True, "exit": True,
     "control": "mullvad", "label": "Mullvad", "detail": "saída de internet"},
    {"name": "wg_casa", "type": "wireguard", "iface": "wg_casa",
     "priority": 20, "routes": [], "manual": True, "exit": False,
     "control": "wg-quick@wg_casa", "label": "WireGuard casa",
     "detail": "10.13.13.0/24 · 192.168.123.0/24"},
    {"name": "netbird-h2o", "type": "netbird", "iface": "wt0",
     "priority": 30, "routes": [], "manual": False, "exit": False,
     "control": "netbird", "label": "NetBird H2O",
     "detail": "host (wt0) — netbird.h2oinnovation.digital"},
    {"name": "netbird-pessoal", "type": "netbird-netns", "iface": "nbh2o0",
     "priority": 40, "routes": [], "manual": False, "exit": False,
     "control": "vpn-split-nbh2o", "netns": "nbh2o",
     "requires": ["vpn-split-netns", "vpn-split-nbh2o-dns"],
     "label": "NetBird pessoal", "detail": "netns — netbird.kolpzs.com"},
]


def load_vpn_registry(cfg: dict) -> list[dict]:
    """Serviços de VPN: os declarados em [vpn.*], ou o conjunto padrão."""
    reg = cfg.get("vpn", {})
    if not reg:
        return [dict(d) for d in DEFAULT_VPN_REGISTRY]
    out = []
    for name, v in reg.items():
        d = dict(v)
        d["name"] = name
        d.setdefault("type", "generic")
        d.setdefault("iface", "")
        d.setdefault("priority", 50)
        d.setdefault("routes", [])
        d.setdefault("manual", False)
        d.setdefault("exit", False)
        d.setdefault("control", "")
        out.append(d)
    return out


def service_active(svc: dict) -> bool:
    typ = svc.get("type")
    if typ == "mullvad":
        return out(["mullvad", "status"]).startswith("Connected")
    if typ == "netbird-netns":
        return link_exists(svc.get("iface") or "nbh2o0")
    iface = svc.get("iface")
    return bool(iface) and link_exists(iface)


def control_vpn(svc: dict, up: bool, pw: str | None = None,
                user: str | None = None) -> subprocess.CompletedProcess:
    """Liga/desliga um serviço de VPN conforme seu `control`."""
    name = svc["name"]
    ctl = svc.get("control") or ""
    if ctl.startswith("pritunl:"):
        pid = ctl.split(":", 1)[1]
        cmd = ["pritunl-client", "start" if up else "stop", pid]
        if up and pw:
            cmd += ["-p", pw]
        if user:
            return run(as_user(user, cmd) if os.geteuid() == 0 else cmd)
        return run(cmd)
    if ctl == "mullvad":
        return run(["mullvad", "connect" if up else "disconnect"])
    if ctl == "netbird":
        if not up:
            return run(["netbird", "down"])
        run(["systemctl", "start", "netbird"])
        time.sleep(0.5)
        st = out(["netbird", "status"])
        if "Management: Disconnected" in st or "NeedsLogin" in st:
            p = run(["timeout", "10", "netbird", "up"])
            if "login" in (p.stdout + p.stderr).lower():
                log(f"{name}: precisa de login (sudo netbird up)", "WARN")
            return p
        return run(["netbird", "up"])
    if not ctl:
        log(f"{name}: sem 'control' definido; ignorando", "WARN")
        return subprocess.CompletedProcess([], 1)
    # unidade systemd (wg-quick@X, vpn-split-nbh2o, ...)
    if up:
        for u in svc.get("requires") or []:
            run(["systemctl", "start", u])
    return run(["systemctl", "start" if up else "stop", ctl])


def build_sources(cfg: dict, wifi: str) -> list[Source]:
    gen = cfg["general"]
    excl = set(cfg["exclude"].get("interfaces", []))
    netns_cfg = cfg["netns"]
    registry = load_vpn_registry(cfg)
    main_routes = ipj("route", "show", "table", "main")
    sources: list[Source] = []

    for svc in registry:
        typ = svc.get("type")
        if typ == "mullvad":
            continue  # saída de internet, não é fonte de rotas
        prio = int(svc.get("priority", 50))
        routes = list(svc.get("routes") or [])

        if typ == "netbird-netns":
            host_if = svc.get("iface") or netns_cfg.get("host_iface", "nbh2o0")
            ns = svc.get("netns") or netns_cfg.get("name", "nbh2o")
            via = netns_cfg.get("via", "10.200.0.2")
            if not link_exists(host_if):
                continue
            s = Source(svc["name"], host_if, prio, "netns", ns=ns, via=via)
            import ipaddress
            ns_subnet = str(ipaddress.ip_interface(
                netns_cfg.get("host_ip", "10.200.0.1/30")).network)
            inner_main = ipj("route", "show", "table", "main", ns=ns)
            inner_nb = table_routes("netbird", ns=ns)
            for pfx, _gw, _dev in route_prefixes(host_if, inner_main) + \
                    route_prefixes("wt0", inner_nb) + route_prefixes("wt1", inner_nb):
                if pfx == ns_subnet:
                    continue
                s.prefixes.append((pfx, via, host_if))
            for ip in netbird_peer_ips(ns):
                s.prefixes.append((f"{ip}/32", via, host_if))
            for cidr in routes:
                s.prefixes.append((cidr, via, host_if))
            sources.append(s)
            continue

        # interfaces deste serviço
        iface = svc.get("iface")
        if typ == "wireguard":
            ifaces = [iface] if iface else wg_ifaces(excl)
        elif typ == "netbird":
            ifaces = [iface] if (iface and link_exists(iface)) else \
                (["wt0"] if link_exists("wt0") else [])
        elif typ in ("pritunl", "openvpn", "generic"):
            ifaces = [iface] if iface else tunnel_ifaces(
                iface or r"^(tun|tap)\d+$", excl)
        else:
            ifaces = [iface] if iface else []

        for dev in ifaces:
            if not dev or not link_exists(dev):
                continue
            s = Source(svc["name"], dev, prio, typ)
            rr = route_prefixes(dev, main_routes)
            if typ == "netbird":
                rr += route_prefixes(dev, table_routes("netbird"))
            rr += [(p, None, dev) for p in iface_subnets(dev)]
            for cidr in routes:
                rr.append((cidr, None, dev))
            s.prefixes = rr
            sources.append(s)

    # autodetecção residual: interfaces wg*/tun* não declaradas (outros serviços)
    covered = {s.iface for s in sources}
    for wg in wg_ifaces(excl):
        if wg not in covered:
            sources.append(Source(wg, wg, 20, "wg"))
    for tun in tunnel_ifaces(r"^tun\d+$", excl):
        if tun not in covered:
            sources.append(Source(tun, tun, 10, "pritunl"))

    # [networks] estático legado: "10.50.0.0/16" = "wg_casa"
    for cidr, target in (cfg.get("networks") or {}).items():
        for s in sources:
            if target in (s.name, s.iface):
                s.prefixes.append((cidr, s.via, s.iface))
                break
        else:
            log(f"config: origem desconhecida para {cidr}: {target}", "WARN")

    # dedup interno
    for s in sources:
        seen = set()
        uniq = []
        for p in s.prefixes:
            if p[0] in seen:
                continue
            seen.add(p[0])
            uniq.append(p)
        s.prefixes = uniq
    return sources


def choose_routes(sources: list[Source], wifi: str, wifi_subnet: str | None) -> tuple[dict, list[str]]:
    chosen: dict[str, dict] = {}
    conflicts: list[str] = []
    for s in sources:
        for pfx, gw, dev in s.prefixes:
            if pfx == "default":
                continue
            if wifi_subnet and pfx == wifi_subnet:
                continue
            cur = chosen.get(pfx)
            if cur is None:
                chosen[pfx] = {"dev": dev, "via": gw, "source": s.name,
                               "priority": s.priority, "kind": s.kind}
                continue
            if s.priority < cur["priority"]:
                conflicts.append(
                    f"{pfx}: {s.name} (prio {s.priority}) vence {cur['source']} (prio {cur['priority']})")
                chosen[pfx] = {"dev": dev, "via": gw, "source": s.name,
                               "priority": s.priority, "kind": s.kind}
            else:
                conflicts.append(
                    f"{pfx}: mantido {cur['source']} (prio {cur['priority']}), ignorado {s.name} (prio {s.priority})")
    return chosen, conflicts


# --------------------------------------------------------------------------- #
# docker
# --------------------------------------------------------------------------- #
def docker_subnets() -> list[str]:
    """Sub-redes Docker que existem no host (inclui o daemon root e o do usuário)."""
    res = set(docker_bridge_subnets())
    if ok(["docker", "info"]):
        for nid in out(["docker", "network", "ls", "-q"]).split():
            try:
                data = json.loads(out(["docker", "network", "inspect", nid]))[0]
            except Exception:
                continue
            for cfg in data.get("IPAM", {}).get("Config") or []:
                sub = cfg.get("Subnet")
                if sub and ":" not in sub:
                    res.add(sub)
    return sorted(res)


def docker_bridge_subnets() -> list[str]:
    """sub-redes conectadas em bridges docker (para detectar conflito exato)."""
    res = []
    for r in ipj("route", "show", "table", "main"):
        dev = r.get("dev", "")
        if dev.startswith(("docker", "br-", "veth")):
            dst = r.get("dst")
            if dst and dst != "default":
                res.append(dst)
    return res


# --------------------------------------------------------------------------- #
# mullvad nft
# --------------------------------------------------------------------------- #
def mullvad_table() -> str | None:
    for t in (DEFAULT_TABLE, "ip mullvad", "ip6 mullvad"):
        if ok(["nft", "list", "table", *t.split()]):
            return t
    return None


def normalize_cidrs(items: list[str]) -> list[str]:
    """Remove IPs/prefixos contidos em outros (set intervalar não aceita overlap)."""
    import ipaddress

    nets = []
    for e in sorted(set(items),
                    key=lambda x: ipaddress.ip_network(x, strict=False).prefixlen):
        n = ipaddress.ip_network(e, strict=False)
        if any(n.subnet_of(m) for m in nets if m.version == n.version):
            continue
        nets.append(n)
    return [str(n) for n in nets]


def nft_sync(table: str, elements: list[str], mark: str, ctmark: str, *, dry_run: bool) -> bool:
    args = table.split()
    if not ok(["nft", "list", "set", *args, NFT_SET]):
        new = dry(["nft", "add", "set", *args, NFT_SET,
                   "{ type ipv4_addr; flags interval; }"], dry_run=dry_run)
        if not new:
            return False
    script = [f"flush set {table} {NFT_SET}"]
    if elements:
        script.append(f"add element {table} {NFT_SET} {{ {', '.join(elements)} }}")
    dry(["nft", "-f", "-"], dry_run=dry_run, stdin="\n".join(script) + "\n")

    spec = (f"ip daddr @{NFT_SET} counter meta mark set {mark} "
            f"ct mark set {ctmark} accept comment \"{NFT_COMMENT}\"")
    current = out(["nft", "-a", "list", "chain", *args, "output"])
    if NFT_COMMENT not in current:
        dry(["nft", "insert", "rule", *args, "output", spec], dry_run=dry_run)
    if ok(["nft", "list", "chain", *args, "forward"]):
        fwd = out(["nft", "-a", "list", "chain", *args, "forward"])
        if NFT_COMMENT not in fwd:
            dry(["nft", "insert", "rule", *args, "forward", spec], dry_run=dry_run)
    return True


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
def dns_set_domains(iface: str, want: list[str], state: dict, *, dry_run: bool) -> None:
    cur = resolvectl_domains(iface)
    old_managed = set(state.get("dns", {}).get(iface, []))
    keep = [t for t in cur if t not in old_managed]
    new = keep + sorted(set(want))
    # remove duplicatas preservando ordem
    seen = set()
    new = [t for t in new if not (t in seen or seen.add(t))]
    if sorted(new) != sorted(cur):
        dry(["resolvectl", "domain", iface, *new], dry_run=dry_run)
    state.setdefault("dns", {})[iface] = sorted(set(want))


# --------------------------------------------------------------------------- #
# estado
# --------------------------------------------------------------------------- #
def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except Exception:
        return {}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2))


# --------------------------------------------------------------------------- #
# apply
# --------------------------------------------------------------------------- #
def ensure_main_rule(*, dry_run: bool = False) -> None:
    """main manda nas rotas específicas, antes da tabela netbird (pref 110).

    `suppress_prefixlength 0` ignora o default da main, então a Mullvad
    continua sendo a saída de internet quando está ligada.
    """
    needle = "from all lookup main suppress_prefixlength 0"
    for line in out(["ip", "rule"]).splitlines():
        if line.strip().startswith("90:") and needle in line:
            return
    dry(["ip", "rule", "add", "pref", "90", "from", "all",
         "lookup", "main", "suppress_prefixlength", "0"], dry_run=dry_run)
    log("regra 90 (main autoritativa) instalada")


def remove_main_rule(*, dry_run: bool = False) -> None:
    needle = "from all lookup main suppress_prefixlength 0"
    for line in out(["ip", "rule"]).splitlines():
        if line.strip().startswith("90:") and needle in line:
            dry(["ip", "rule", "del", "pref", "90", "from", "all",
                 "lookup", "main", "suppress_prefixlength", "0"], dry_run=dry_run)
            return


def apply(cfg: dict, *, dry_run: bool = False) -> int:
    gen = cfg["general"]
    wifi = gen.get("wifi_iface", "auto")
    dr = default_route()
    if not dr:
        log("sem rota default; abortando", "ERROR")
        return 1
    if wifi in ("auto", "", None):
        wifi = dr["dev"]
    if dr["dev"] != wifi:
        dr = default_route(wifi)
        if not dr:
            log(f"sem rota default em {wifi}; abortando", "ERROR")
            return 1
    wifi_gw = dr.get("gateway")
    wifi_dns = resolvectl_dns(wifi)
    wifi_subnet = None
    for p in iface_subnets(wifi):
        wifi_subnet = p
        break

    state = load_state()
    state.setdefault("routes", {})
    state.setdefault("nft", [])
    state.setdefault("dns", {})

    sources = build_sources(cfg, wifi)
    chosen, conflicts = choose_routes(sources, wifi, wifi_subnet)

    # --- 0. main autoritativa para rotas específicas (vence a tabela netbird) -- #
    ensure_main_rule(dry_run=dry_run)

    # --- 1. remove rotas default-like de VPN (full tunnel) ------------------ #
    protected = {s.iface for s in sources}
    if gen.get("manage_full_tunnel", True):
        for r in ipj("route", "show", "table", "main"):
            dst = r.get("dst")
            dev = r.get("dev")
            if dst in ("0.0.0.0/1", "128.0.0.0/1") and dev in protected:
                if dry(["ip", "route", "del", dst, "dev", dev], dry_run=dry_run):
                    log(f"full-tunnel removido: {dst} dev {dev}")

    # --- 2. conflitos exatos com Docker/local ------------------------------ #
    local = {}
    for r in ipj("route", "show", "table", "main"):
        if r.get("protocol") == "kernel" and r.get("scope") == "link":
            local[r.get("dst")] = r.get("dev")
    policy = gen.get("on_exact_conflict", "skip")
    local_conflicts = []
    for pfx, info in list(chosen.items()):
        ldev = local.get(pfx)
        if ldev and ldev != info["dev"] and ldev.startswith(("docker", "br-", "veth")):
            msg = f"{pfx}: VPN {info['source']} x local {ldev}"
            local_conflicts.append(msg)
            if policy != "vpn":
                log(f"conflito exato (local vence): {msg}", "WARN")
                del chosen[pfx]
            else:
                log(f"conflito exato (VPN vence): {msg}", "WARN")

    # --- 3. aplica rotas ---------------------------------------------------- #
    present: dict[str, list[dict]] = {}
    for r in ipj("route", "show", "table", "main"):
        d = r.get("dst")
        if d and d != "default":
            present.setdefault(d, []).append(r)

    desired_routes = {}
    for pfx, info in sorted(chosen.items()):
        cur = present.get(pfx) or []
        same = any(r.get("dev") == info["dev"]
                   and (r.get("gateway") or None) == (info["via"] or None)
                   for r in cur)
        if same:
            continue  # já está correto; não mexe
        cmd = ["ip", "route", "replace", pfx]
        if info["via"]:
            cmd += ["via", info["via"]]
        cmd += ["dev", info["dev"]]
        if dry(cmd, dry_run=dry_run):
            desired_routes[pfx] = {"dev": info["dev"], "via": info["via"],
                                   "source": info["source"]}

    # remove rotas que aplicamos e não são mais desejadas
    for pfx, info in state["routes"].items():
        if pfx in chosen:
            continue
        if pfx in ("0.0.0.0/1", "128.0.0.0/1"):
            continue
        cmd = ["ip", "route", "del", pfx]
        if info.get("via"):
            cmd += ["via", info["via"]]
        cmd += ["dev", info["dev"]]
        if dry(cmd, dry_run=dry_run):
            log(f"rota obsoleta removida: {pfx}")
    state["routes"] = desired_routes

    # --- 4/5. endpoints + domínios que sempre saem pela Wi-Fi --------------- #
    pinned: dict[str, str] = {}
    endpoint_ips: list[str] = []
    endpoints_via = "mullvad" if FALLBACK_FLAG.exists() else gen.get("endpoints_via", "wifi")
    # O DNS da Wi-Fi também precisa sair pela Wi-Fi (na faculdade é IP público e,
    # com a Mullvad ligada, seria engolido pelo túnel/kill-switch).
    for srv in wifi_dns:
        if IPV4_RE.match(srv):
            pinned[srv] = "wifi-dns"
    if endpoints_via == "wifi" and wifi_gw:
        for host in cfg["endpoints"].get("wifi", []):
            for ip in resolve_host(host, wifi_dns):
                endpoint_ips.append(ip)
                pinned[ip] = f"endpoint:{host}"
        if not endpoint_ips:
            # DNS falhou (ex.: logo após conectar a Mullvad): mantém os pins anteriores
            for ip, kind in state.get("pins", {}).items():
                if str(kind).startswith("endpoint"):
                    endpoint_ips.append(ip)
                    pinned[ip] = kind
            if endpoint_ips:
                log("resolução dos endpoints falhou; reutilizando pins anteriores", "WARN")

    wifi_domains = list(cfg["domains"].get("wifi", []))
    for f in cfg["domains"].get("wifi_files", []):
        wifi_domains += read_domain_file(f)
    wifi_domains = sorted({d for d in wifi_domains if d})

    college_ips: list[str] = []
    ttl = int(cfg["domains"].get("ttl", 900))
    cache = state.get("college", {})
    if (cache.get("ips") and cache.get("dns") == wifi_dns
            and (time.time() - cache.get("ts", 0)) < ttl):
        college_ips = list(cache["ips"])
    else:
        for d in wifi_domains:
            for ip in resolve_host(d, wifi_dns):
                if ip not in college_ips:
                    college_ips.append(ip)
        state["college"] = {"ts": time.time(), "ips": college_ips,
                            "dns": wifi_dns}
    for ip in college_ips:
        pinned[ip] = "college"

    # aplica pins (/32 pela Wi-Fi) e remove os que sobraram
    for ip in pinned:
        if not wifi_gw:
            continue
        cur = present.get(f"{ip}/32") or []
        if any(r.get("dev") == wifi and (r.get("gateway") or None) == wifi_gw for r in cur):
            continue
        dry(["ip", "route", "replace", f"{ip}/32", "via", wifi_gw, "dev", wifi],
            dry_run=dry_run)
    for ip in state.get("pins", {}):
        if ip not in pinned:
            dry(["ip", "route", "del", f"{ip}/32"], dry_run=dry_run)
            log(f"pin removido: {ip}")
    state["pins"] = pinned

    if wifi_domains:
        dns_set_domains(wifi, [f"~{d}" for d in wifi_domains], state, dry_run=dry_run)

    # --- 5b. DNS do netns H2O (upstream = DNS do Wi-Fi atual) -------------- #
    ns_if = cfg["netns"].get("host_iface", "nbh2o0")
    if link_exists(ns_if):
        ups = Path("/run/vpn-split/nbh2o-upstream")
        want = "".join(f"nameserver {d}\n" for d in wifi_dns) or "nameserver 1.1.1.1\n"
        if not ups.exists() or ups.read_text() != want:
            if dry_run:
                log(f"DRY atualizaria upstream do dnsmasq H2O: {want.strip()}")
            else:
                ups.parent.mkdir(parents=True, exist_ok=True)
                ups.write_text(want)
                run(["systemctl", "reload-or-restart", "vpn-split-nbh2o-dns"])
                log("upstream DNS do netns H2O atualizado")

    # --- 6. nft / kill-switch da Mullvad ---------------------------------- #
    table = mullvad_table()
    nft_elements = []
    if table:
        ns_net = None
        try:
            import ipaddress
            ns_net = str(ipaddress.ip_interface(
                cfg["netns"].get("host_ip", "10.200.0.1/30")).network)
        except Exception:
            pass
        nft_elements = sorted(set(
            list(chosen.keys())
            + list(pinned.keys())
            + docker_subnets()
            + list(cfg["exclude"].get("extra_cidrs", []))
            + ([wifi_subnet] if wifi_subnet else [])
            + ([ns_net] if ns_net else [])
        ))
        nft_elements = normalize_cidrs(nft_elements)
        nft_sync(table, nft_elements,
                 cfg["mullvad"].get("mark", "0x6d6f6c65"),
                 cfg["mullvad"].get("ct_mark", "0x00000f41"),
                 dry_run=dry_run)
        log(f"nft: {len(nft_elements)} prefixos excluídos na tabela {table}")
    else:
        log("Mullvad desligada (sem tabela nft) — exclusões serão aplicadas ao conectar")
    state["nft"] = nft_elements

    save_state(state)

    # --- 7. status resumido ------------------------------------------------ #
    if conflicts:
        for c in conflicts:
            log(f"conflito: {c}", "WARN")
    if local_conflicts:
        for c in local_conflicts:
            log(f"conflito local: {c}", "WARN")
    log(f"ok: {len(chosen)} rotas, wifi={wifi} gw={wifi_gw} dns={','.join(wifi_dns) or '-'}")
    return 0


def resolve_host(host: str, dns: list[str]) -> list[str]:
    if IPV4_RE.match(host):
        return [host.split("/")[0]]
    for attempt in range(2):
        ips = []
        for server in dns[:1]:
            p = run(["dig", "+short", "+time=2", "+tries=1", "@" + server, "A", host])
            ips += [l.strip() for l in p.stdout.splitlines() if IPV4_RE.match(l.strip())]
        if ips:
            return sorted(set(ips))
        if attempt == 0:
            time.sleep(0.5)
    p = run(["getent", "ahostsv4", host])
    ips = [l.split()[0] for l in p.stdout.splitlines() if IPV4_RE.match(l.split()[0])]
    return sorted(set(ips))


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #
def desktop_user(cfg: dict) -> str:
    u = cfg["general"].get("user")
    if u:
        return u
    if os.environ.get("SUDO_USER"):
        return os.environ["SUDO_USER"]
    import pwd
    name = pwd.getpwuid(os.getuid()).pw_name
    return "" if name == "root" else name


def desktop_home(user: str) -> str:
    import pwd
    try:
        return pwd.getpwnam(user).pw_dir
    except KeyError:
        return f"/home/{user}"


def as_user(user: str, cmd: list[str]) -> list[str]:
    return ["runuser", "-u", user, "--", "env", f"HOME={desktop_home(user)}", *cmd]


def pritunl_profiles(user: str | None = None) -> list[dict]:
    """Lista os profiles do Pritunl (o CLI como root vê vazio; usa o usuário)."""
    cmd = ["pritunl-client", "list"]
    p = run(as_user(user, cmd) if (os.geteuid() == 0 and user) else cmd)
    if p.stdout.count("|") < 3:
        p = run(cmd)
    res = []
    for line in p.stdout.splitlines():
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) < 8 or cols[0] in ("ID", "") or set(cols[0]) <= set("-"):
            continue
        res.append({"id": cols[0], "name": cols[1], "state": cols[3],
                    "online": cols[5], "server": cols[6], "client": cols[7]})
    return res


def netbird_json(ns: str | None = None, sock: str | None = None) -> dict | None:
    cmd = ["netbird"]
    if sock:
        cmd += ["--daemon-addr", sock]
    cmd += ["status", "--json"]
    p = run(cmd, ns=ns)
    if p.returncode != 0 or not p.stdout.strip():
        return None
    try:
        return json.loads(p.stdout)
    except Exception:
        return None


def wg_peer_ages(iface: str) -> list[dict]:
    """Pares WireGuard com a idade do handshake (em segundos)."""
    p = run(["wg", "show", iface, "latest-handshakes"])
    now = time.time()
    res = []
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            res.append({"pubkey": parts[0][:12] + "…",
                        "age": max(0, int(now - int(parts[1])))})
    return res


def live_status(cfg: dict) -> dict:
    """Estado 'vivo' das conexões: serviços + peers (para a tela em tempo real)."""
    registry = load_vpn_registry(cfg)
    user = desktop_user(cfg)
    host_nb = netbird_json()
    ns = cfg["netns"].get("name", "nbh2o")
    ns_exists = ns in out(["ip", "netns", "list"]).split()
    netns_nb = netbird_json(ns=ns, sock="unix:///run/vpn-split/netbird-h2o.sock") \
        if ns_exists else None

    def nb_entry(nb):
        e = {"connected": False, "self_ip": "", "fqdn": "", "peers": []}
        if not nb:
            return e
        e["connected"] = bool((nb.get("management") or {}).get("connected"))
        e["self_ip"] = nb.get("netbirdIp") or ""
        e["fqdn"] = nb.get("fqdn") or ""
        for pr in (nb.get("peers") or {}).get("details") or []:
            lat = pr.get("latency")
            lat_s = ""
            if isinstance(lat, int) and lat > 0:
                lat_s = f"{lat/1_000_000:.0f} ms" if lat >= 1_000_000 else f"{lat} ms"
            e["peers"].append({
                "name": pr.get("fqdn") or (pr.get("netbirdIp") or ""),
                "ip": pr.get("netbirdIp") or "",
                "status": pr.get("status") or "Disconnected",
                "latency": lat_s or pr.get("latency") or "",
            })
        return e

    services = []
    for svc in registry:
        typ = svc.get("type")
        entry = {"name": svc["name"], "label": svc.get("label") or svc["name"],
                 "type": typ, "connected": False, "detail": "",
                 "self_ip": "", "fqdn": "", "peers": []}
        if typ == "netbird":
            entry.update(nb_entry(host_nb))
        elif typ == "netbird-netns":
            entry.update(nb_entry(netns_nb))
            entry["detail"] = f"netns {ns}"
        elif typ == "wireguard":
            iface = svc.get("iface") or "wg_casa"
            up = link_exists(iface)
            entry["connected"] = up
            entry["detail"] = iface
            if up:
                ages = wg_peer_ages(iface)
                entry["peers"] = [{
                    "name": a["pubkey"], "ip": "", "status":
                    "up" if a["age"] < 180 else "down", "age": a["age"],
                } for a in ages]
                entry["connected"] = any(a["age"] < 180 for a in ages)
        elif typ == "mullvad":
            m = out(["mullvad", "status"]).strip()
            entry["connected"] = m.startswith("Connected")
            entry["detail"] = m.split("\n")[1].strip() \
                if "\n" in m and entry["connected"] else ""
        elif typ == "pritunl":
            profs = pritunl_profiles(user)
            entry["connected"] = any(p["state"] == "Active" for p in profs)
            entry["detail"] = ", ".join(
                f"{p['name']}: {'on' if p['state'] == 'Active' else 'off'}"
                for p in profs)
        else:
            entry["connected"] = service_active(svc)
            entry["detail"] = svc.get("iface") or svc.get("control") or ""
        services.append(entry)
    return {"services": services, "ts": time.time()}


def collect_status(cfg: dict) -> dict:
    dr = default_route()
    wifi = cfg["general"].get("wifi_iface", "auto")
    if wifi in ("auto", "", None) and dr:
        wifi = dr["dev"]
    wifi = wifi or "wlo1"

    sources = build_sources(cfg, wifi)
    chosen, conflicts = choose_routes(sources, wifi, None)

    table = mullvad_table()
    nft_n, nft_rule = 0, False
    if table:
        cur = out(["nft", "list", "set", *table.split(), NFT_SET])
        nft_n = len(set(re.findall(r"\d+\.\d+\.\d+\.\d+", cur)))
        nft_rule = NFT_COMMENT in out(["nft", "-a", "list", "chain", *table.split(), "output"])

    full = []
    for r in ipj("route", "show", "table", "main"):
        if r.get("dst") in ("0.0.0.0/1", "128.0.0.0/1"):
            full.append({"prefix": r["dst"], "via": r.get("gateway"),
                         "dev": r.get("dev")})

    docker = docker_subnets()
    clash = sorted(set(chosen) & set(docker_bridge_subnets()))

    dns = {}
    for iface in {wifi, "wt0", cfg["netns"].get("host_iface", "nbh2o0")}:
        if iface and link_exists(iface):
            doms = [d for d in resolvectl_domains(iface) if d.startswith("~")]
            if doms:
                dns[iface] = doms

    ns = cfg["netns"].get("name", "nbh2o")
    ns_exists = ns in out(["ip", "netns", "list"]).split()
    ns_status = ""
    if ns_exists:
        st = out(["ip", "netns", "exec", ns, "netbird",
                  "--daemon-addr", "unix:///run/vpn-split/netbird-h2o.sock",
                  "status"]).strip().splitlines()
        ns_status = next((l.strip() for l in st if l.strip()), "")

    mull = out(["mullvad", "status"]).strip()
    mull_connected = mull.startswith("Connected")

    profiles = pritunl_profiles(desktop_user(cfg))
    controls = []
    for svc in load_vpn_registry(cfg):
        nm = svc["name"]
        note = ""
        if svc.get("type") == "netbird-netns" and ns_status:
            note = ns_status.replace("Daemon status: ", "")
        if svc.get("exit"):
            note = "saída de internet" + (f" · {note}" if note else "")
        controls.append({
            "target": nm,
            "name": svc.get("label") or nm,
            "active": service_active(svc),
            "detail": svc.get("detail") or (svc.get("iface") or svc.get("type")),
            "note": note,
        })
    for pr in profiles:
        controls.append({
            "target": f"pritunl:{pr['id']}", "name": pr["name"],
            "active": pr["state"] == "Active",
            "detail": f"servidor {pr['server']} · cliente {pr['client']}",
            "note": pr["online"] if pr["state"] == "Active" else "",
        })

    st = load_state().get("pins", {})
    kinds: dict[str, int] = {}
    for _ip, kind in st.items():
        k = str(kind).split(":", 1)[0]
        kinds[k] = kinds.get(k, 0) + 1
    pins = {"count": len(st), "kinds": kinds,
            "college": sorted(ip for ip, k in st.items()
                              if str(k).startswith("college"))}

    pname, ssid, prof = active_profile(cfg)

    return {
        "wifi": {"iface": wifi,
                 "gateway": dr.get("gateway") if dr else None,
                 "dns": resolvectl_dns(wifi)},
        "routes": [{"prefix": p, "via": i["via"], "dev": i["dev"],
                    "source": i["source"]} for p, i in sorted(chosen.items())],
        "sources": [{"name": s.name, "iface": s.iface, "kind": s.kind,
                     "up": link_exists(s.iface),
                     "prefixes": sorted({p for p, _, _ in s.prefixes})}
                    for s in sources],
        "full_tunnel": full,
        "mullvad": {"connected": mull_connected, "table": table,
                    "nft_elements": nft_n, "nft_rule": nft_rule},
        "fallback": FALLBACK_FLAG.exists(),
        "pins": pins,
        "profile": {"name": pname, "ssid": ssid,
                    "mullvad": bool(prof.get("mullvad", False)),
                    "netbird": bool(prof.get("netbird", True)),
                    "netbird_h2o": bool(prof.get("netbird_h2o", True))},
        "docker": docker,
        "docker_clash": clash,
        "dns": dns,
        "conflicts": conflicts,
        "netns": {"name": ns, "exists": ns_exists, "status": ns_status},
        "pritunl": profiles,
        "controls": controls,
    }


def status(cfg: dict, as_json: bool = False) -> int:
    data = collect_status(cfg)
    if as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    w = data["wifi"]
    print(f"Wi-Fi          : {w['iface']}  gw={w['gateway'] or '-'}  "
          f"dns={','.join(w['dns']) or '-'}")
    p = data["profile"]
    print(f"Perfil         : {p['name']} (SSID '{p['ssid']}') — "
          f"Mullvad {'on' if p['mullvad'] else 'off'}, "
          f"NetBird {'on' if p['netbird'] else 'off'}, "
          f"H2O {'on' if p['netbird_h2o'] else 'off'}")
    print()

    print("Rotas administradas (tabela main):")
    for r in data["routes"]:
        via = f"via {r['via']} " if r["via"] else ""
        print(f"  {r['prefix']:<20} {via}dev {r['dev']:<10} [{r['source']}]")
    if not data["routes"]:
        print("  (nenhuma)")

    print("\nRotas default-like de VPN ainda na main:")
    if data["full_tunnel"]:
        for r in data["full_tunnel"]:
            print(f"  {r['prefix']} via {r['via'] or '-'} dev {r['dev']}")
    else:
        print("  (nenhuma)")

    m = data["mullvad"]
    print(f"\nMullvad        : {'conectada, tabela ' + m['table'] if m['connected'] else 'desligada'}")
    if m["table"]:
        print(f"  exclusões    : {m['nft_elements']} entradas   "
              f"regra mark/accept: {'sim' if m['nft_rule'] else 'NÃO'}")

    print("\nBypass Wi-Fi   : "
          f"{data['pins']['count']} IPs ("
          + ", ".join(f"{k}={v}" for k, v in data["pins"]["kinds"].items())
          + ")")

    print("\nDocker:")
    for s in data["docker"]:
        print(f"  {s}")
    if data["docker_clash"]:
        print(f"  !! conflito exato com VPN: {', '.join(data['docker_clash'])}")

    print("\nDNS roteado:")
    for iface, doms in data["dns"].items():
        print(f"  {iface}: {', '.join(doms)}")

    if data["conflicts"]:
        print("\nConflitos entre VPNs:")
        for c in data["conflicts"]:
            print(f"  {c}")

    n = data["netns"]
    if n["exists"]:
        print(f"\nNetBird H2O    : netns {n['name']} ativo — {n['status']}")
    else:
        print("\nNetBird H2O    : netns ausente")
    return 0


# --------------------------------------------------------------------------- #
# clear
# --------------------------------------------------------------------------- #
def clear(cfg: dict, *, dry_run: bool = False) -> int:
    state = load_state()
    remove_main_rule(dry_run=dry_run)
    for pfx, info in state.get("routes", {}).items():
        cmd = ["ip", "route", "del", pfx]
        if info.get("via"):
            cmd += ["via", info["via"]]
        cmd += ["dev", info["dev"]]
        if dry(cmd, dry_run=dry_run):
            log(f"rota removida: {pfx}")
    for ip in state.get("pins", {}):
        dry(["ip", "route", "del", f"{ip}/32"], dry_run=dry_run)
    for iface, doms in state.get("dns", {}).items():
        if not doms:
            continue
        cur = resolvectl_domains(iface)
        new = [t for t in cur if t not in set(doms)]
        if new != cur:
            dry(["resolvectl", "domain", iface, *new], dry_run=dry_run)
    table = mullvad_table()
    if table:
        if ok(["nft", "list", "set", *table.split(), NFT_SET]):
            dry(["nft", "flush", "set", *table.split(), NFT_SET], dry_run=dry_run)
            dry(["nft", "delete", "set", *table.split(), NFT_SET], dry_run=dry_run)
        for chain in ("output", "forward"):
            if not ok(["nft", "list", "chain", *table.split(), chain]):
                continue
            for line in out(["nft", "-a", "list", "chain", *table.split(), chain]).splitlines():
                if NFT_COMMENT in line:
                    h = line.split("handle", 1)[-1].strip().split()[0]
                    dry(["nft", "delete", "rule", *table.split(), chain, "handle", h],
                        dry_run=dry_run)
    if not dry_run:
        STATE_PATH.unlink(missing_ok=True)
    log("estado limpo")
    return 0


# --------------------------------------------------------------------------- #
# netns do NetBird H2O
# --------------------------------------------------------------------------- #
def _nft_script(lines: list[str], *, ns: str | None, dry_run: bool) -> None:
    dry(["nft", "-f", "-"], ns=ns, dry_run=dry_run, stdin="\n".join(lines) + "\n")


def netns_prepare(cfg: dict, *, dry_run: bool = False) -> int:
    n = cfg["netns"]
    name = n.get("name", "nbh2o")
    hif = n.get("host_iface", "nbh2o0")
    nif = n.get("ns_iface", "nbh2o1")
    host_ip = n.get("host_ip", "10.200.0.1/30")
    ns_ip = n.get("ns_ip", "10.200.0.2/30")
    mtu = int(n.get("mtu", 1280))

    if name not in out(["ip", "netns", "list"]).split():
        dry(["ip", "netns", "add", name], dry_run=dry_run)

    if not link_exists(hif):
        dry(["ip", "link", "add", hif, "type", "veth", "peer", "name", nif], dry_run=dry_run)
        dry(["ip", "link", "set", nif, "netns", name], dry_run=dry_run)
        dry(["ip", "addr", "add", host_ip, "dev", hif], dry_run=dry_run)
    dry(["ip", "link", "set", hif, "mtu", str(mtu), "up"], dry_run=dry_run)

    inside = [
        f"ip addr replace {ns_ip} dev {nif}",
        f"ip link set {nif} mtu {mtu} up",
        "ip link set lo up",
        "ip route replace default via " + host_ip.split("/")[0],
        "sysctl -qw net.ipv4.ip_forward=1",
    ]
    for cmd in inside:
        dry(cmd.split(), ns=name, dry_run=dry_run)

    # NAT dentro do ns: tudo que sai pelo wt0 recebe o IP do NetBird
    _nft_script([
        "add table ip vpnnsnat",
        "flush table ip vpnnsnat",
        "add chain ip vpnnsnat postrouting { type nat hook postrouting priority 100 ; }",
        'add rule ip vpnnsnat postrouting oifname "wt0" masquerade comment "vpn-split-netns"',
    ], ns=name, dry_run=dry_run)

    # NAT no host: 10.200.0.0/30 -> wlo1 (ou Mullvad, se ligada)
    host_subnet = host_ip.rsplit(".", 1)[0] + ".0/30"
    if not ok(["nft", "list", "table", "inet", "vpnsplit"]):
        _nft_script([
            "add table inet vpnsplit",
            "flush table inet vpnsplit",
            "add chain inet vpnsplit postrouting { type nat hook postrouting priority 100 ; }",
            f'add rule inet vpnsplit postrouting ip saddr {host_subnet} '
            f'oifname != "{hif}" masquerade comment "vpn-split-netns"',
        ], ns=None, dry_run=dry_run)
    dry(["sysctl", "-qw", "net.ipv4.ip_forward=1"], dry_run=dry_run)

    ensure_netbird_h2o_config(dry_run=dry_run)

    # DNS privado do namespace: 127.0.0.1 -> dnsmasq do ns -> DNS do Wi-Fi
    if not dry_run:
        Path("/run/vpn-split").mkdir(parents=True, exist_ok=True)
        Path("/run/vpn-split/nbh2o-resolv.conf").write_text("nameserver 127.0.0.1\n")
    dr = default_route()
    wdns = resolvectl_dns(dr["dev"]) if dr else []
    ups = Path("/run/vpn-split/nbh2o-upstream")
    want = "".join(f"nameserver {d}\n" for d in wdns) or "nameserver 1.1.1.1\n"
    if not ups.exists() or ups.read_text() != want:
        if dry_run:
            log(f"DRY escreveria {ups}: {want.strip()}")
        else:
            ups.write_text(want)

    # host usa o dnsmasq do ns para os domínios da empresa
    if link_exists(hif):
        dry(["resolvectl", "dns", hif, n.get("dns", "10.200.0.2")], dry_run=dry_run)
        doms = n.get("dns_domains", [])
        dry(["resolvectl", "domain", hif, *doms], dry_run=dry_run)

    log(f"netns {name} pronto ({host_ip} <-> {ns_ip})")
    return 0


def netns_destroy(cfg: dict, *, dry_run: bool = False) -> int:
    name = cfg["netns"].get("name", "nbh2o")
    if name in out(["ip", "netns", "list"]).split():
        dry(["ip", "netns", "delete", name], dry_run=dry_run)
    if ok(["nft", "list", "table", "inet", "vpnsplit"]):
        _nft_script(["delete table inet vpnsplit"], ns=None, dry_run=dry_run)
    log(f"netns {name} removido")
    return 0


def ensure_netbird_h2o_config(*, dry_run: bool = False) -> None:
    """Importa o profile do NetBird que roda no netns (re-importa se a chave mudou)."""
    dst = Path("/etc/vpn-split/netbird-h2o/config.json")
    # qual profile roda no netns: "H2O" (padrão) ou "pessoal" (default.json)
    try:
        prof = load_config().get("netns", {}).get("profile", "H2O")
    except Exception:
        prof = "H2O"

    cands = []
    if prof == "pessoal":
        cands = ["/var/lib/netbird/default.json"]
    else:
        cands = sorted(glob.glob("/var/lib/netbird/*/*.json"))

    for cand in cands:
        try:
            data = json.loads(Path(cand).read_text())
        except Exception:
            continue
        if prof != "pessoal" and data.get("Name") != prof:
            continue
        data["DisableDNS"] = True          # DNS é tratado pelo host/dnsmasq
        data["DisableNotifications"] = True
        # re-importa se a chave mudou (ex.: profile re-adicionado)
        if dst.exists():
            try:
                if json.loads(dst.read_text()).get("PrivateKey") == data.get("PrivateKey"):
                    return
            except Exception:
                pass
        if dry_run:
            log(f"DRY criaria {dst} a partir de {cand}")
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(data, indent=2))
        os.chmod(dst, 0o600)
        log(f"config do netns importada de {cand} (profile '{prof}')")
        return
    log(f"profile '{prof}' não encontrado em /var/lib/netbird", "WARN")


def netns_status(cfg: dict) -> int:
    n = cfg["netns"]
    name = n.get("name", "nbh2o")
    if name not in out(["ip", "netns", "list"]).split():
        print(f"netns {name}: não existe")
        return 1
    sock = "unix:///run/vpn-split/netbird-h2o.sock"
    print(f"netns {name}:")
    print(out(["ip", "netns", "exec", name, "ip", "-br", "addr"]).strip())
    print("\nrotas internas (main):")
    print(out(["ip", "netns", "exec", name, "ip", "route"]).strip())
    print("\nrotas internas (netbird):")
    print(out(["ip", "netns", "exec", name, "ip", "route", "show", "table", "netbird"]).strip())
    print("\nnetbird status:")
    print(out(["ip", "netns", "exec", name, "netbird", "--daemon-addr", sock,
               "status"]).strip())
    return 0


def netns_login(cfg: dict) -> int:
    name = cfg["netns"].get("name", "nbh2o")
    sock = "unix:///run/vpn-split/netbird-h2o.sock"
    log("abrindo fluxo de login SSO do NetBird H2O (conclua no navegador)...")
    return subprocess.call(["ip", "netns", "exec", name, "netbird",
                            "--daemon-addr", sock, "up"])


def netbird_peer_ips(ns: str) -> list[str]:
    """IPs dos peers do NetBird dentro do ns (para rotas /32 no host)."""
    sock = "unix:///run/vpn-split/netbird-h2o.sock"
    p = run(["netbird", "--daemon-addr", sock, "status", "--json"], ns=ns)
    if p.returncode != 0 or not p.stdout.strip():
        return []
    try:
        data = json.loads(p.stdout)
    except Exception:
        return []
    ips: set[str] = set()
    for peer in (data.get("peers") or {}).get("details") or []:
        ip = str(peer.get("netbirdIp") or "").split("/")[0]
        if IPV4_RE.match(ip) and ip.startswith("100."):
            ips.add(ip)
    return sorted(ips)


def wg_allowed_ips(iface: str) -> list[str]:
    p = Path(f"/etc/wireguard/{iface}.conf")
    res = []
    if not p.exists():
        return res
    for line in p.read_text().splitlines():
        line = line.strip()
        if line.lower().startswith("allowedips"):
            _, _, val = line.partition("=")
            res += [x.strip() for x in val.split(",") if x.strip()]
    return res


def clean_routes_for_iface(iface: str, prefixes: list[str]) -> None:
    """Remove rotas que outro cliente instalou para os prefixos desta VPN."""
    for pfx in prefixes:
        if pfx in ("0.0.0.0/0", "::/0") or ":" in pfx:
            continue
        for line in out(["ip", "route", "show", pfx]).splitlines():
            if f"dev {iface}" in line:
                continue
            log(f"removendo rota conflitante antes de subir {iface}: {line.strip()}")
            run(["ip", "route", "del", pfx])


def ctl(cfg: dict, target: str, up: bool, pw: str | None = None) -> int:
    """Liga/desliga uma VPN (por nome do registro ou alvo legado) e reconcilia."""
    registry = load_vpn_registry(cfg)
    svc = next((s for s in registry if s["name"] == target), None)

    if svc is None:  # alvos legados / dinâmicos
        if target.startswith("pritunl:"):
            svc = {"name": target, "type": "pritunl", "iface": "", "control": target}
        elif target.startswith("wg"):
            iface = target.split(":", 1)[1] if ":" in target else "wg_casa"
            svc = {"name": target, "type": "wireguard", "iface": iface,
                   "control": f"wg-quick@{iface}"}
        elif target == "netbird":
            svc = {"name": "netbird", "type": "netbird", "control": "netbird"}
        elif target == "netbird-h2o":
            svc = {"name": "netbird-h2o", "type": "netbird-netns",
                   "control": "vpn-split-nbh2o",
                   "requires": ["vpn-split-netns", "vpn-split-nbh2o-dns"]}
        elif target == "mullvad":
            svc = {"name": "mullvad", "type": "mullvad", "control": "mullvad"}
        else:
            log(f"alvo desconhecido: {target}", "ERROR")
            return 2

    # WireGuard: limpa rotas conflitantes antes de subir (evita "File exists")
    if up and svc.get("type") == "wireguard":
        iface = svc.get("iface") or (target.split(":", 1)[1] if ":" in target else target)
        if iface:
            clean_routes_for_iface(iface, wg_allowed_ips(iface))

    p = control_vpn(svc, up, pw, user=desktop_user(cfg))
    if p.returncode != 0:
        log(f"{target}: falhou ({p.stderr.strip() or p.stdout.strip()})", "WARN")
    time.sleep(1)
    apply(cfg)
    return 0 if p.returncode == 0 else 1


def set_fallback(cfg: dict, on: bool, *, dry_run: bool = False) -> int:
    if on:
        if not dry_run:
            FALLBACK_FLAG.write_text("endpoints pelo Mullvad (Wi-Fi sem UDP)\n")
        log("fallback ON: tráfego externo dos túneis passará pela Mullvad")
        apply(cfg, dry_run=dry_run)
        if not dry_run:
            run(["mullvad", "connect"])
            log("Mullvad: conectando (obfuscação automática)")
    else:
        if not dry_run:
            FALLBACK_FLAG.unlink(missing_ok=True)
        log("fallback OFF: tráfego externo dos túneis volta pela Wi-Fi")
        apply(cfg, dry_run=dry_run)
    return 0


# --------------------------------------------------------------------------- #
# perfis automáticos por SSID
# --------------------------------------------------------------------------- #
def normalize_ssid(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def current_ssid() -> str:
    """SSID da rede Wi-Fi ativa (via NetworkManager)."""
    for _ in range(2):
        for line in out(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]).splitlines():
            if line.startswith("yes:"):
                ssid = line.split(":", 1)[1].strip()
                if ssid:
                    return ssid
        time.sleep(0.3)
    return out(["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", "wlo1"]).strip()


def active_profile(cfg: dict) -> tuple[str, str, dict]:
    ssid = current_ssid()
    profs = cfg.get("profiles", {})
    trusted = {normalize_ssid(s) for s in profs.get("trusted_ssids", [])}
    name = "trusted" if normalize_ssid(ssid) in trusted else "default"
    return name, ssid, profs.get(name, {})


def apply_profile(cfg: dict, *, force: bool = False) -> tuple[str, bool]:
    """Aplica o perfil correspondente ao SSID atual. Retorna (nome, mudou)."""
    name, ssid, prof = active_profile(cfg)
    state = load_state()
    prev = state.get("profile", {})
    if not force and prev.get("name") == name and prev.get("ssid") == ssid:
        return name, False

    log(f"perfil '{name}' para SSID '{ssid}'")
    registry = load_vpn_registry(cfg)
    user = desktop_user(cfg)

    # quais serviços o perfil quer ligados + qual é a saída (exit)
    if "vpn" in prof:
        want = set(prof.get("vpn") or [])
        exit_name = prof.get("exit") or ""
    else:  # compat com o esquema antigo (mullvad/netbird/netbird_h2o)
        want = set()
        if prof.get("netbird", True):
            want.add("netbird-pessoal")
        if prof.get("netbird_h2o", True):
            want.add("netbird-h2o")
        exit_name = "mullvad" if prof.get("mullvad", False) else ""

    for svc in registry:
        nm = svc["name"]
        if svc.get("exit"):
            up = nm == exit_name
        elif nm in want:
            up = True
        elif svc.get("manual"):
            continue  # manual e fora do perfil: não mexe
        else:
            up = False
        control_vpn(svc, up, user=user)

    state["profile"] = {"name": name, "ssid": ssid, "ts": time.time()}
    save_state(state)
    return name, True


# --------------------------------------------------------------------------- #
# watch
# --------------------------------------------------------------------------- #
def watch(cfg: dict) -> int:
    interval = int(cfg["general"].get("reconcile_interval", 15))
    log(f"watch iniciado (intervalo {interval}s)")
    proc = subprocess.Popen(["ip", "monitor", "route", "address", "link"],
                            stdout=subprocess.PIPE, text=True, bufsize=1)
    dirty = True
    last_apply = 0.0
    last_event = 0.0

    def reconcile():
        try:
            apply_profile(cfg)
            apply(cfg)
        except Exception as exc:  # nunca morre por erro pontual
            log(f"apply falhou: {exc}", "ERROR")

    while True:
        now = time.time()
        # 1) aplica no máximo 1.2s depois do último evento
        if dirty and (now - last_event) >= 1.2:
            reconcile()
            dirty = False
            last_apply = time.time()
            continue
        # 2) reconciliação periódica (DNS/endpoints/nft da Mullvad)
        if (now - last_apply) >= interval:
            reconcile()
            last_apply = time.time()
            dirty = False
            continue

        if dirty:
            wait = max(0.05, 1.2 - (now - last_event))
        else:
            wait = max(0.05, min(1.0, interval - (now - last_apply)))
        r, _, _ = select.select([proc.stdout], [], [], wait)
        if not r:
            continue
        line = proc.stdout.readline()
        if not line:
            log("ip monitor encerrou; reiniciando", "WARN")
            time.sleep(1)
            proc = subprocess.Popen(["ip", "monitor", "route", "address", "link"],
                                    stdout=subprocess.PIPE, text=True, bufsize=1)
            dirty = True
            continue
        last_event = time.time()
        dirty = True
        log(f"evento: {line.strip()}")

        # 3) full-tunnel do Pritunl: remove o /1 no mesmo instante, sem esperar
        #    o debounce (senão a internet inteira fica no túnel por segundos)
        m = re.match(r"^(0\.0\.0\.0/1|128\.0\.0\.0/1) via (\S+) dev (\S+)", line.strip())
        if m and re.match(r"^(tun\d+|wt\d+|wg[^ ]*)$", m.group(3)) \
                and "mullvad" not in m.group(3):
            p = run(["ip", "route", "del", m.group(1), "via", m.group(2), "dev", m.group(3)])
            if p.returncode == 0:
                log(f"full-tunnel removido na hora: {m.group(1)} dev {m.group(3)}", "WARN")


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(prog="vpn-split")
    ap.add_argument("action", nargs="?", default="apply",
                    choices=["apply", "status", "clear", "watch",
                             "netns-prepare", "netns-destroy", "netns-status",
                             "netns-login", "fallback", "ctl", "ui",
                             "profile", "profile-apply"])
    ap.add_argument("value", nargs="?", default=None)
    ap.add_argument("value2", nargs="?", default=None)
    ap.add_argument("--config", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    global CONFIG_PATH
    if args.config:
        CONFIG_PATH = Path(args.config)
    cfg = load_config()

    if os.geteuid() != 0 and args.action in ("apply", "clear", "watch",
                                             "netns-prepare", "netns-destroy",
                                             "netns-status", "netns-login",
                                             "fallback", "ctl", "profile-apply"):
        raise SystemExit("rode como root (sudo vpn-split ...)")

    if args.action == "apply":
        return apply(cfg, dry_run=args.dry_run)
    if args.action == "status":
        return status(cfg, as_json=args.json)
    if args.action == "clear":
        return clear(cfg, dry_run=args.dry_run)
    if args.action == "watch":
        return watch(cfg)
    if args.action == "netns-prepare":
        return netns_prepare(cfg, dry_run=args.dry_run)
    if args.action == "netns-destroy":
        return netns_destroy(cfg, dry_run=args.dry_run)
    if args.action == "netns-status":
        return netns_status(cfg)
    if args.action == "netns-login":
        return netns_login(cfg)
    if args.action == "fallback":
        if args.value not in ("on", "off"):
            raise SystemExit("uso: vpn-split fallback on|off")
        return set_fallback(cfg, args.value == "on", dry_run=args.dry_run)
    if args.action == "ctl":
        if not args.value or args.value2 not in ("on", "off"):
            raise SystemExit("uso: vpn-split ctl <alvo> on|off")
        return ctl(cfg, args.value, args.value2 == "on")
    if args.action == "profile":
        name, ssid, prof = active_profile(cfg)
        print(f"SSID atual     : '{ssid}'")
        print(f"Perfil ativo   : {name}")
        print(f"  mullvad      : {'ligada' if prof.get('mullvad') else 'desligada'}")
        print(f"  netbird      : {'ligada' if prof.get('netbird', True) else 'desligada'}")
        print(f"  netbird_h2o  : {'ligada' if prof.get('netbird_h2o', True) else 'desligada'}")
        print(f"SSIDs trusted  : {', '.join(cfg.get('profiles', {}).get('trusted_ssids', []))}")
        return 0
    if args.action == "profile-apply":
        name, changed = apply_profile(cfg, force=True)
        apply(cfg, dry_run=args.dry_run)
        log(f"perfil '{name}' aplicado")
        return 0
    if args.action == "ui":
        print("http://127.0.0.1:8787")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
