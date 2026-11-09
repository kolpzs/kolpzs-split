#!/usr/bin/env python3
"""Dashboard local do vpn-split — http://127.0.0.1:8787

Escuta apenas no loopback. Roda como root porque precisa de ip/nft/systemctl.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import tomllib
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, "/usr/local/lib/vpn-split")
import vpn_split as vs  # noqa: E402


def _ui_cfg() -> dict:
    try:
        return vs.load_config().get("ui") or {}
    except Exception:
        return {}


CONFIG = Path(os.environ.get("VPN_SPLIT_CONFIG", "/etc/vpn-split/config.toml"))
PORT = int(os.environ.get("VPN_SPLIT_UI_PORT", str(_ui_cfg().get("port", 8787))))
BIND = os.environ.get("VPN_SPLIT_UI_BIND", _ui_cfg().get("bind", "127.0.0.1"))
TOKEN_FILE = Path(os.environ.get(
    "VPN_SPLIT_UI_TOKEN_FILE", _ui_cfg().get("token_file", "/etc/vpn-split/ui.token")))


def load_token() -> str:
    """Lê o token do painel; gera um (root-only) se ainda não existir."""
    if TOKEN_FILE.exists():
        t = TOKEN_FILE.read_text().strip()
        if t:
            return t
    t = secrets.token_hex(16)
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(t + "\n")
    os.chmod(TOKEN_FILE, 0o600)
    return t


TOKEN = load_token()

HTML = r"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>vpn-split</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0f1115;
      --surface: #171a21;
      --surface-2: #12151b;
      --line: #262b36;
      --line-2: #1d212b;
      --txt: #e6e8ee;
      --muted: #8b93a7;
      --accent: #4f8cff;
      --ok: #2ea043;
      --ok-txt: #5fd374;
      --warn: #d7a62e;
      --bad: #d9534f;
      --bad-txt: #ff8b87;
      --radius: 12px;
      --radius-sm: 8px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--txt);
      font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    }

    /* ---------- header ---------- */
    header {
      position: sticky;
      top: 0;
      z-index: 5;
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 14px;
      padding: 14px 22px;
      background: var(--surface-2);
      border-bottom: 1px solid var(--line);
    }

    h1 { margin: 0 6px 0 0; font-size: 17px; letter-spacing: .3px; }

    header .muted {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    /* ---------- layout ---------- */
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 20px 22px 64px;
    }

    h2 {
      margin: 0 0 12px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: .12em;
      text-transform: uppercase;
      color: var(--muted);
    }

    section {
      margin-bottom: 16px;
      padding: 16px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius);
    }

    .grid2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }

    .muted { color: var(--muted); font-size: 12.5px; }
    .err { color: var(--bad-txt); font-size: 12.5px; }
    .note { font-size: 12px; color: var(--warn); word-break: break-word; }
    .spacer { flex: 1; }

    /* ---------- cards / pills / buttons ---------- */
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(255px, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }

    .card {
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding: 14px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius);
    }
    .card.on { border-color: rgba(46, 160, 67, .45); }

    .row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .pill {
      padding: 2px 9px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      white-space: nowrap;
    }
    .pill.pon { background: rgba(46, 160, 67, .18); color: var(--ok-txt); }
    .pill.poff { background: rgba(217, 83, 79, .15); color: var(--bad-txt); }

    .actions { display: flex; gap: 8px; margin-top: auto; }

    button {
      padding: 7px 13px;
      font-size: 13px;
      color: var(--txt);
      background: #232836;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      cursor: pointer;
    }
    button:hover { border-color: #3a4254; }
    button:disabled { opacity: .45; cursor: wait; }
    button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    button.danger { background: transparent; border-color: rgba(217, 83, 79, .5); color: var(--bad-txt); }

    .switch {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 12.5px;
    }

    /* ---------- tabelas ---------- */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }

    th, td {
      padding: 6px 8px;
      text-align: left;
      border-bottom: 1px solid var(--line);
    }

    th {
      font-size: 11.5px;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--muted);
    }

    tr:last-child td { border-bottom: none; }

    /* ---------- código / formulário ---------- */
    code, pre, textarea { font-family: var(--mono); }

    pre {
      max-height: 260px;
      margin: 0;
      padding: 12px;
      overflow: auto;
      font-size: 12px;
      background: #0b0d11;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
    }

    textarea {
      width: 100%;
      min-height: 260px;
      padding: 12px;
      font-size: 12.5px;
      color: var(--txt);
      background: #0b0d11;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
    }

    .banner {
      margin-bottom: 16px;
      padding: 10px 14px;
      color: #e8cd8b;
      background: rgba(215, 182, 107, .12);
      border: 1px solid rgba(215, 182, 107, .4);
      border-radius: 10px;
    }

    a { color: var(--accent); }

    /* ---------- gate (token) ---------- */
    .gate {
      position: fixed;
      inset: 0;
      z-index: 50;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, .72);
    }

    .gatebox {
      display: flex;
      flex-direction: column;
      gap: 12px;
      width: 340px;
      padding: 24px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius);
    }
    .gatebox h2 { margin: 0; }
    .gatebox p { margin: 0; }
    .gatebox input {
      padding: 9px;
      font-family: var(--mono);
      color: var(--txt);
      background: #0b0d11;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
    }

    /* ---------- conexões (tempo real) ---------- */
    .livegrid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 12px;
    }

    .livecard {
      display: flex;
      flex-direction: column;
      gap: 6px;
      min-width: 0;
      padding: 12px;
      overflow: hidden;
      background: var(--surface-2);
      border: 1px solid var(--line);
      border-radius: 10px;
    }
    .livecard.on { border-color: rgba(63, 185, 80, .5); }

    .livecard .muted, .card .muted {
      min-width: 0;
      overflow-wrap: anywhere;
    }

    .peer {
      display: flex;
      align-items: center;
      gap: 6px;
      min-width: 0;
      padding: 4px 0;
      font-size: 12px;
      border-top: 1px solid var(--line-2);
    }
    .peer:first-child { border-top: none; }

    .pname {
      flex: 1;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .pip, .pmeta { flex: none; }
    .pip { color: var(--muted); }
    .pmeta { color: var(--muted); font-variant-numeric: tabular-nums; }

    .dot {
      width: 9px;
      height: 9px;
      flex: none;
      border-radius: 50%;
    }
    .dot.on { background: #3fb950; box-shadow: 0 0 6px #3fb950; }
    .dot.off { background: var(--bad); }
    .dot.idle { background: var(--warn); }

    @media (max-width: 800px) {
      .grid2 { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div id="gate" class="gate" style="display:none">
    <div class="gatebox">
      <h2>Token de acesso</h2>
      <p class="muted">Informe o token do painel (<code>/etc/vpn-split/ui.token</code>).</p>
      <input id="tok" type="password" placeholder="token" autocomplete="off">
      <button class="primary" onclick="setToken()">Entrar</button>
      <div class="err" id="gateerr"></div>
    </div>
  </div>

  <header>
    <h1>vpn-split</h1>
    <span class="muted" id="wifi">carregando…</span>
    <span class="muted" id="profile"></span>
    <span class="spacer"></span>
    <label class="switch">
      <input type="checkbox" id="fb" onchange="setFallback(this.checked)">
      fallback UDP (túneis via Mullvad)
    </label>
    <button onclick="act('profile-apply')">Reaplicar perfil</button>
    <button onclick="act('apply')">Aplicar</button>
  </header>

  <main>
    <div id="banner"></div>
    <div class="err" id="err"></div>
    <div class="cards" id="cards"></div>

    <section>
      <h2>Conexões (tempo real)</h2>
      <div class="livegrid" id="live"></div>
    </section>

    <div class="grid2">
      <section>
        <h2>Rotas administradas (main)</h2>
        <table>
          <thead>
            <tr>
              <th>Prefixo</th>
              <th>Via</th>
              <th>Dev</th>
              <th>Origem</th>
            </tr>
          </thead>
          <tbody id="routes"></tbody>
        </table>
        <div id="fulltunnel"></div>
      </section>

      <section>
        <h2>Saúde</h2>
        <table><tbody id="health"></tbody></table>
        <div class="muted" id="dns" style="margin-top:10px"></div>
      </section>
    </div>

    <section>
      <h2>Configuração (<code>/etc/vpn-split/config.toml</code>)</h2>
      <details>
        <summary class="muted" style="cursor:pointer">mostrar / editar</summary>
        <textarea id="cfg" spellcheck="false"></textarea>
        <div class="actions" style="margin-top:10px">
          <button class="primary" onclick="saveCfg()">Salvar e aplicar</button>
          <button onclick="loadCfg()">Recarregar</button>
          <span class="muted" id="cfgmsg"></span>
        </div>
      </details>
    </section>

    <section>
      <h2>Log</h2>
      <pre id="log">…</pre>
    </section>
  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    const esc = (s) => String(s ?? '').replace(
      /[&<>"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]),
    );
    const getToken = () => localStorage.getItem('vpn-token') || '';

    (function bootstrapToken() {
      const q = new URLSearchParams(location.search);
      const t = q.get('token');
      if (t) {
        localStorage.setItem('vpn-token', t);
        history.replaceState(null, '', location.pathname);
      }
    })();

    function gateCheck() {
      if (getToken()) {
        $('gate').style.display = 'none';
        return true;
      }
      $('gate').style.display = 'flex';
      return false;
    }

    function setToken() {
      const v = $('tok').value.trim();
      if (!v) return;
      localStorage.setItem('vpn-token', v);
      location.reload();
    }

    async function api(path, opts = {}) {
      const t = getToken();
      const sep = path.includes('?') ? '&' : '?';
      const url = path + (t ? sep + 'token=' + encodeURIComponent(t) : '');
      const r = await fetch(url, { cache: 'no-store', ...opts });
      const txt = await r.text();
      let data;
      try { data = JSON.parse(txt); } catch { data = { error: txt }; }
      if (!r.ok) throw new Error(data.error || txt);
      return data;
    }

    async function act(action, extra = {}) {
      try {
        await api('/api/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action, ...extra }),
        });
        $('err').textContent = '';
      } catch (e) {
        $('err').textContent = 'Erro: ' + e.message;
      }
      setTimeout(refresh, 1000);
    }

    async function ctl(target, up, btn) {
      if (btn) {
        btn.disabled = true;
        btn.textContent = up ? 'ligando…' : 'desligando…';
      }
      const extra = { target, up };
      if (up && target.startsWith('pritunl:')) {
        const v = prompt('Senha/OTP do Pritunl (deixe vazio se a sessão ainda é válida):');
        if (v === null) {
          if (btn) { btn.disabled = false; btn.textContent = 'Ligar'; }
          return;
        }
        if (v) extra.pw = v;
      }
      await act('ctl', extra);
    }

    async function setFallback(on) {
      await act('fallback', { on });
    }

    function render(d) {
      $('wifi').textContent =
        `${d.wifi.iface} · gw ${d.wifi.gateway || '-'} · DNS ${d.wifi.dns.join(', ') || '-'}`;
      $('profile').textContent = `Perfil ${d.profile.name} · SSID '${d.profile.ssid}'`;
      $('fb').checked = !!d.fallback;

      $('banner').innerHTML = (d.netns.status || '').includes('NeedsLogin')
        ? '<div class="banner">NetBird precisa de login: ' +
          '<code>sudo vpn-split netns-login</code> (uma vez)</div>'
        : '';

      $('cards').innerHTML = d.controls.map((c) => `
        <div class="card ${c.active ? 'on' : ''}">
          <div class="row">
            <strong>${esc(c.name)}</strong>
            <span class="pill ${c.active ? 'pon' : 'poff'}">${c.active ? 'ligado' : 'desligado'}</span>
          </div>
          <div class="muted">${esc(c.detail)}</div>
          ${c.note ? `<div class="note">${esc(c.note)}</div>` : ''}
          <div class="actions">
            ${c.active
              ? `<button class="danger" onclick="ctl('${esc(c.target)}', false, this)">Desligar</button>`
              : `<button class="primary" onclick="ctl('${esc(c.target)}', true, this)">Ligar</button>`}
          </div>
        </div>`).join('');

      $('routes').innerHTML = d.routes.length
        ? d.routes.map((r) => `
            <tr>
              <td><code>${esc(r.prefix)}</code></td>
              <td>${esc(r.via || '-')}</td>
              <td><code>${esc(r.dev)}</code></td>
              <td class="muted">${esc(r.source)}</td>
            </tr>`).join('')
        : '<tr><td colspan="4" class="muted">nenhuma</td></tr>';

      $('fulltunnel').innerHTML = d.full_tunnel.length
        ? `<div class="err" style="margin-top:10px">full-tunnel ativo: ` +
          `${d.full_tunnel.map((r) => esc(r.prefix + ' dev ' + r.dev)).join(', ')}</div>`
        : '';

      const mv = d.mullvad;
      $('health').innerHTML = `
        <tr><td>Mullvad</td><td>${mv.connected
          ? '<span class="pill pon">conectada</span>'
          : '<span class="pill poff">desligada</span>'}</td></tr>
        <tr><td>Exclusões nft</td><td>${mv.connected
          ? `${mv.nft_elements} prefixos · regra ${mv.nft_rule ? 'ok' : '<b class="err">ausente</b>'}`
          : '-'}</td></tr>
        <tr><td>Docker</td><td>${d.docker.join(', ') || '-'}${d.docker_clash.length ? ' <b class="err">conflito!</b>' : ''}</td></tr>
        <tr><td>Conflitos VPN</td><td>${d.conflicts.length ? esc(d.conflicts.join(' · ')) : 'nenhum'}</td></tr>
        <tr><td>NetBird H2O</td><td>${d.netns.exists ? 'netns ativo' : 'ausente'}</td></tr>
        <tr><td>Bypass Wi-Fi</td><td>${d.pins.count} IPs (${Object.entries(d.pins.kinds)
          .map(([k, v]) => k + ': ' + v).join(' · ')})</td></tr>`;

      $('dns').textContent = 'DNS roteado: ' +
        Object.entries(d.dns).map(([k, v]) => `${k}: ${v.join(' ')}`).join(' | ');
    }

    async function refresh() {
      if (!gateCheck()) return;
      try {
        render(await api('/api/status'));
        $('err').textContent = '';
      } catch (e) {
        $('err').textContent = 'Erro ao atualizar: ' + e.message;
      }
      try {
        const l = await api('/api/log');
        $('log').textContent = l.log || '';
      } catch {}
    }

    async function loadCfg() {
      try {
        $('cfg').value = (await api('/api/config')).text;
        $('cfgmsg').textContent = '';
      } catch (e) {
        $('cfgmsg').textContent = e.message;
      }
    }

    async function saveCfg() {
      try {
        await api('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: $('cfg').value }),
        });
        $('cfgmsg').textContent = 'salvo e aplicado';
        setTimeout(refresh, 800);
      } catch (e) {
        $('cfgmsg').textContent = 'erro: ' + e.message;
      }
    }

    async function refreshLive() {
      if (!gateCheck()) return;
      try {
        const d = await api('/api/live');
        $('live').innerHTML = (d.services || []).map((s) => {
          const cls = s.connected ? 'on' : 'off';
          const peers = (s.peers || []).length
            ? s.peers.map((p) => {
                const ps = (p.status === 'Connected' || p.status === 'up') ? 'on'
                  : (p.status === 'Idle') ? 'idle' : 'off';
                const info = (p.age != null) ? p.age + 's' : (p.latency || p.status || '');
                return '<div class="peer">' +
                  '<span class="dot ' + ps + '"></span>' +
                  '<span class="pname" title="' + esc(p.name || p.ip) + '">' + esc(p.name || p.ip) + '</span>' +
                  '<span class="pip">' + esc(p.ip) + '</span>' +
                  '<span class="pmeta">' + esc(info) + '</span>' +
                  '</div>';
              }).join('')
            : '<div class="peer muted">sem peers</div>';
          return '<div class="livecard ' + cls + '">' +
            '<div class="row"><strong>' + esc(s.label) + '</strong>' +
            '<span class="dot ' + cls + '"></span></div>' +
            '<div class="muted">' + esc(s.self_ip || s.fqdn || s.detail || s.type) + '</div>' +
            peers + '</div>';
        }).join('') || '<div class="muted">carregando…</div>';
      } catch (e) {
        $('live').innerHTML = '';
      }
    }

    refresh();
    loadCfg();
    setInterval(refresh, 5000);
    setInterval(refreshLive, 5000);
  </script>
</body>
</html>
"""


def log_tail() -> str:
    p = subprocess.run(
        ["journalctl", "-u", "vpn-split", "-u", "vpn-split-nbh2o",
         "-u", "vpn-split-nbh2o-dns", "-n", "120", "--no-pager", "-o", "cat"],
        text=True, capture_output=True)
    return p.stdout[-20000:]


class Handler(BaseHTTPRequestHandler):
    server_version = "vpn-split-ui"

    def log_message(self, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json")

    def _path(self) -> str:
        return urllib.parse.urlsplit(self.path).path

    def _authorized(self) -> bool:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        qt = q.get("token", [None])[0]
        auth = self.headers.get("Authorization", "")
        hdr = auth[7:].strip() if auth.startswith("Bearer ") else None
        return qt == TOKEN or hdr == TOKEN

    def do_GET(self) -> None:
        try:
            if self._path() in ("/", "/index.html"):
                self._send(200, HTML.encode(), "text/html; charset=utf-8")
            elif self._path().startswith("/api/"):
                if not self._authorized():
                    self._json(403, {"error": "token inválido"})
                    return
                if self._path() == "/api/status":
                    self._json(200, vs.collect_status(vs.load_config()))
                elif self._path() == "/api/config":
                    self._json(200, {"text": CONFIG.read_text()})
                elif self._path() == "/api/log":
                    self._json(200, {"log": log_tail()})
                elif self._path() == "/api/live":
                    self._json(200, vs.live_status(vs.load_config()))
                else:
                    self._json(404, {"error": "not found"})
            else:
                self._json(404, {"error": "not found"})
        except Exception as exc:
            self._json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            if self._path().startswith("/api/") and not self._authorized():
                self._json(403, {"error": "token inválido"})
                return
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n) or b"{}")
            if self._path() == "/api/action":
                self._json(200, self._action(body))
            elif self._path() == "/api/config":
                self._json(200, self._save_config(body.get("text", "")))
            else:
                self._json(404, {"error": "not found"})
        except Exception as exc:
            self._json(400, {"error": str(exc)})

    def _action(self, body: dict) -> dict:
        act = body.get("action")
        cfg = vs.load_config()
        if act == "apply":
            rc = vs.apply(cfg)
        elif act == "clear":
            rc = vs.clear(cfg)
        elif act == "ctl":
            rc = vs.ctl(cfg, body["target"], bool(body.get("up")),
                        body.get("pw") or None)
        elif act == "profile-apply":
            vs.apply_profile(cfg, force=True)
            rc = vs.apply(cfg)
        elif act == "fallback":
            rc = vs.set_fallback(cfg, bool(body.get("on")))
        else:
            raise ValueError(f"ação desconhecida: {act}")
        return {"ok": rc == 0}

    def _save_config(self, text: str) -> dict:
        try:
            tomllib.loads(text)
        except Exception as exc:
            raise ValueError(f"TOML inválido: {exc}")
        backup = CONFIG.with_suffix(
            f".toml.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        backup.write_text(CONFIG.read_text())
        CONFIG.write_text(text)
        os.chmod(CONFIG, 0o644)
        vs.apply(vs.load_config())
        return {"ok": True, "backup": str(backup)}


def main() -> int:
    if os.geteuid() != 0:
        print("rode como root (serviço vpn-split-ui)", file=sys.stderr)
        return 1
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"vpn-split ui em http://{BIND}:{PORT} (token: {TOKEN_FILE})", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
