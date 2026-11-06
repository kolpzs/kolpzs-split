# Arquitetura

## Modelo de roteamento

```
main (fonte da verdade)
 ├─ <sub-rede LAN/Wi-Fi>     → wlo1
 ├─ <sub-redes Docker>       → bridges locais
 ├─ 10.13.13.0/24            → wg_casa          (WireGuard)
 ├─ 100.96.0.0/16            → wt0              (NetBird pessoal)
 ├─ 10.200.0.0/30            → nbh2o0           (veth do NetBird H2O)
 ├─ <sub-redes do tun*>      → tun0/tun1        (Pritunl/OpenVPN)
 └─ 0.0.0.0/0                → Mullvad          (só quando ligada)
```

Regras de ouro:

1. Nenhuma VPN ganha `0.0.0.0/0` — exceto a de saída (Mullvad).
2. `0.0.0.0/1` e `128.0.0.0/1` (full-tunnel) são removidos na hora.
3. A `main` é autoritativa para rotas específicas via
   `ip rule add pref 90 from all lookup main suppress_prefixlength 0`
   (`suppress_prefixlength 0` ignora o default da main, então a Mullvad
   continua sendo a saída).

## Kill-switch da Mullvad

Com a Mullvad conectada, o daemon instala um `nft` com `output`/`forward`
`policy drop`. Para que as redes internas continuem acessíveis sem desligar o
kill-switch, o `vpn-split` cria um set `vpn_split_v4` (intervalo) na tabela
`inet mullvad` e insere, no topo das chains `output`/`forward`:

```
ip daddr @vpn_split_v4 meta mark set 0x6d6f6c65 ct mark set 0x00000f41 accept
```

São exatamente os marks que o `mullvad-exclude` usa. O set contém: prefixos das
VPNs, Docker, LAN, endpoints dos túneis, IPs dos domínios "pinned" e o DNS da
Wi-Fi.

## DNS split

systemd-resolved com domínios de roteamento (`~dominio`):

- `~dominio-da-faculdade/empresa` no link da Wi-Fi → resolve pelo DNS da Wi-Fi.
- `~h2oinnovation.digital` no veth do netns → resolve pelo dnsmasq do namespace.

O DNS da Wi-Fi (que pode ser IP público, ex.: o da faculdade) também é pinado
`/32` pela Wi-Fi e entra no set nft, senão a Mullvad engoliria a resolução.

## Segundo NetBird em network namespace

Dois clientes NetBird não podem coexistir no mesmo host: usam a mesma tabela
`netbird`/regra 110, o mesmo `nft table ip netbird` e o mesmo `state.json`
(`/var/lib/netbird/state.json`). Por isso o segundo roda em:

- network namespace `nbh2o` + veth `10.200.0.0/30`, com NAT no host e no ns;
- mount namespace privado (`unshare -m`), com `/var/lib/netbird` e
  `/etc/ssh/ssh_config.d` bindados para diretórios próprios;
- dnsmasq no ns + `resolv.conf` privado (`nameserver 127.0.0.1`).

O host enxerga as redes do segundo NetBird por rotas `via 10.200.0.2`.

## Perfis por SSID

O watcher lê o SSID (NetworkManager) e seleciona `trusted` (SSIDs listados) ou
`default` (qualquer outro), ligando/desligando Mullvad + NetBirds. O dispatcher
do NetworkManager reaplica na troca de rede; o watcher confere a cada 15 s.
wg_casa/Pritunl ficam manuais.

## Componentes

| Arquivo | Papel |
|---|---|
| `vpn_split.py` | núcleo: rotas, nft, DNS, netns, perfis, CLI |
| `vpn_split_ui.py` | painel web (HTTP no loopback, token) |
| `netns-netbird.sh` | sobe o segundo NetBird no netns |
| `systemd/*.service` | watcher, painel, netns, daemon H2O, dns |
| `contrib/90-vpn-split` | dispatcher do NetworkManager |
