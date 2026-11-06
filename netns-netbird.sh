#!/usr/bin/env bash
# Inicia o segundo cliente NetBird (H2O) dentro do network namespace nbh2o.
#
# Isolamento duplo:
#   * network namespace  -> interface/rotas/nft próprios, sem colidir com o
#     wt0/tabela `netbird`/regra 110 do NetBird pessoal;
#   * mount namespace    -> /var/lib/netbird e /etc/ssh/ssh_config.d privados,
#     senão o daemon limpa o state.json e o SSH config do daemon do host.
set -euo pipefail

NS="${VPN_SPLIT_NETNS:-nbh2o}"
PRIV="/var/lib/vpn-split/netbird-h2o"
SSHDIR="/var/lib/vpn-split/ssh_config.d"
CONF="/etc/vpn-split/netbird-h2o/config.json"
SOCK="/run/vpn-split/netbird-h2o.sock"
LOG="/var/log/vpn-split/netbird-h2o.log"

mkdir -p "$PRIV" "$SSHDIR" /var/log/vpn-split /run/vpn-split
chmod 700 "$PRIV"

if [ ! -f "$CONF" ]; then
    echo "config H2O ausente: $CONF (rode: vpn-split netns-prepare)" >&2
    exit 1
fi

exec ip netns exec "$NS" unshare -m --propagation private /bin/bash -c "
    mount --bind '$PRIV' /var/lib/netbird
    mount --bind '$SSHDIR' /etc/ssh/ssh_config.d
    mount --bind /run/vpn-split/nbh2o-resolv.conf /etc/resolv.conf
    exec /usr/bin/netbird service run \
        --config '$CONF' \
        --daemon-addr 'unix://$SOCK' \
        --disable-profiles \
        --disable-update-settings \
        --service netbird-h2o \
        --log-file '$LOG' \
        --log-level info
"
