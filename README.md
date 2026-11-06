# kolpzs-split

Roteamento por destino para múltiplas VPNs no mesmo notebook Linux: cada VPN
acessa **apenas** a rede dela, a Mullvad (ou outra VPN de saída) é a única que
pode tomar a internet, e **perfis** são aplicados automaticamente conforme o
Wi-Fi conectado.

Sem subir a internet inteira por uma VPN só. Com kill-switch da Mullvad
respeitado, DNS split por domínio, Docker fora de colisão e um painel local.

## O que resolve

- Várias VPNs simultâneas, cada uma só nas suas sub-redes (WireGuard, NetBird,
  Pritunl/OpenVPN, etc.).
- Full-tunnel empurrado por cliente (`0.0.0.0/1` + `128.0.0.0/1`) é removido
  automaticamente.
- Com a Mullvad ligada, as redes internas continuam acessíveis sem furar o
  kill-switch (marcação `nft` no estilo `mullvad-exclude`).
- DNS split: domínios escolhidos resolvem pela Wi-Fi atual; domínios da empresa
  resolvem pelo DNS interno.
- Dois clientes NetBird ao mesmo tempo (o segundo isolado em network namespace).
- Perfis por SSID (rede de confiança vs. qualquer outra).
- Painel web local com token.

## Requisitos

Linux com `iproute2`, `nftables`, `systemd-resolved`, `NetworkManager`, Python
3.11+ (stdlib apenas, sem dependências), e os clientes de VPN que você for usar.

## Instalação

```bash
sudo ./install.sh
```

Isso instala o código em `/usr/local/lib/vpn-split/`, o CLI em
`/usr/local/sbin/vpn-split`, o config em `/etc/vpn-split/config.toml`, as units
systemd e o dispatcher do NetworkManager. O painel ganha um token gerado em
`/etc/vpn-split/ui.token`.

Depois edite `/etc/vpn-split/config.toml` (SSIDs de confiança, domínios,
endpoints) e rode:

```bash
sudo vpn-split apply
```

## Comandos

```bash
sudo vpn-split status            # rotas, perfil, Mullvad, bypass, conflitos
sudo vpn-split status --json
sudo vpn-split apply             # reconcilia (idempotente)
sudo vpn-split clear             # desfaz o que o vpn-split criou

sudo vpn-split profile           # SSID/perfil atual
sudo vpn-split profile-apply     # reaplica o perfil agora

sudo vpn-split ctl <alvo> on|off # wg_casa | netbird | netbird-h2o | mullvad | pritunl:<id>
sudo vpn-split netns-login       # login SSO do segundo NetBird (netns)
sudo vpn-split fallback on|off   # Wi-Fi sem UDP: túneis externos via Mullvad
sudo vpn-split ui                # URL do painel
```

Painel: `http://127.0.0.1:8787` — ele pede o token (gate) ou use
`http://127.0.0.1:8787/?token=<token>`. O token fica em
`/etc/vpn-split/ui.token` (gerado no `install.sh`).

## Como funciona (resumo)

Ver `docs/ARCHITECTURE.md` para o detalhe.

- Tabela `main` como fonte da verdade; cada VPN ganha rota específica.
- Regra `pref 90 lookup main suppress_prefixlength 0` (rotas específicas vencem;
  o default não é capturado pela main).
- Set `nft` `vpn_split_v4` na tabela `inet mullvad` com
  `meta mark 0x6d6f6c65` + `ct mark 0xf41 accept` para furar o kill-switch.
- DNS split via domínios de roteamento (`~dominio`) do systemd-resolved.
- Segundo NetBird em `netns` + mount namespace (dois clientes NetBird colidem
  na tabela `netbird`/regra 110/state.json).

## Adicionar um novo serviço de VPN

Tudo é declarativo em `[vpn.<nome>]` no `config.toml` — veja
`config.example.toml` para o esquema completo. Exemplo (Tailscale):

```toml
[vpn.tailscale]
type     = "generic"      # wireguard | netbird | netbird-netns | pritunl | mullvad | generic
iface    = "tailscale0"   # se vazio, autodetecção (tun*/wg*)
priority = 25             # menor vence quando há sobreposição de prefixos
routes   = ["100.64.0.0/10"]   # CIDRs estáticos além dos descobertos
control  = "tailscaled"   # unidade systemd (ou "netbird" | "mullvad" | "pritunl:<id>")
manual   = true           # fora dos perfis (liga/desliga só por ctl/painel)
```

Os perfis referenciam os serviços por nome (`vpn = [...]`, `exit = "..."`).
Serviços `manual` não são tocados pelo perfil. Sem `[vpn.*]`, o conjunto padrão
(mullvad, wg_casa, netbird pessoal e netbird H2O) é usado.

## Limitações conhecidas

- As marcas `nft` (`0x6d6f6c65`/`0xf41`) são específicas da Mullvad; para outra
  VPN de saída, ajuste em `[mullvad]`.
- O segundo NetBird em netns segue convenções de nomes (`vpn-split-<netns>`).
- O painel roda como root no loopback (é uma ferramenta de laptop; revise o
  token antes de expor).

## Licença

MIT — veja `LICENSE`.
