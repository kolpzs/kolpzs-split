#!/usr/bin/env bash
# kolpzs-split — instalador.
# Copia os arquivos para /usr/local e /etc, instala as units systemd e gera o
# token do painel. Não sobrescreve o config.toml existente.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
ETC="${ETC:-/etc/vpn-split}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "rode como root: sudo ./install.sh" >&2
    exit 1
fi

install -d "$PREFIX/lib/vpn-split" "$PREFIX/sbin" "$ETC"
install -m 755 "$HERE/vpn_split.py"     "$PREFIX/lib/vpn-split/vpn_split.py"
install -m 755 "$HERE/vpn_split_ui.py"  "$PREFIX/lib/vpn-split/vpn_split_ui.py"
install -m 755 "$HERE/netns-netbird.sh" "$PREFIX/lib/vpn-split/netns-netbird.sh"
install -m 755 "$HERE/vpn-split"        "$PREFIX/sbin/vpn-split"

if [ ! -f "$ETC/config.toml" ]; then
    install -m 644 "$HERE/config.example.toml" "$ETC/config.toml"
    echo "config criado em $ETC/config.toml (edite!)"
fi

install -m 644 "$HERE"/systemd/*.service /etc/systemd/system/
install -m 755 "$HERE/contrib/90-vpn-split" /etc/NetworkManager/dispatcher.d/90-vpn-split

# token do painel (se ainda não existir)
if [ ! -s "$ETC/ui.token" ]; then
    python3 -c "import secrets; print(secrets.token_hex(16))" > "$ETC/ui.token"
    chmod 600 "$ETC/ui.token"
    echo "token do painel: $(cat "$ETC/ui.token")"
fi

systemctl daemon-reload

cat <<'MSG'
Pronto. Próximos passos:
  1. edite /etc/vpn-split/config.toml
  2. sudo systemctl enable --now vpn-split vpn-split-ui
  3. painel: http://127.0.0.1:8787 (token em /etc/vpn-split/ui.token)
MSG
