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
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>vpn-split</title>
<style>
  :root { color-scheme: dark; --bg:#0f1115; --card:#171a21; --line:#262b36;
          --txt:#e6e8ee; --muted:#8b93a7; --ok:#2ea043; --bad:#d9534f;
          --accent:#4f8cff; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
         font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  header { position:sticky; top:0; z-index:5; background:#12151b;
           border-bottom:1px solid var(--line); padding:14px 22px;
           display:flex; gap:18px; align-items:center; flex-wrap:wrap; }
  h1 { font-size:17px; margin:0 10px 0 0; letter-spacing:.3px; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.12em;
       color:var(--muted); margin:0 0 10px; }
  main { padding:20px 22px 60px; max-width:1180px; }
  .pill { padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; }
  .pon { background:rgba(46,160,67,.18); color:#5fd374; }
  .poff { background:rgba(217,83,79,.15); color:#ff8b87; }
  .cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(255px,1fr));
           gap:12px; margin-bottom:22px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px;
          padding:14px; display:flex; flex-direction:column; gap:8px; }
  .card.on { border-color:rgba(46,160,67,.45); }
  .row { display:flex; justify-content:space-between; align-items:center; gap:8px; }
  .muted { color:var(--muted); font-size:12.5px; }
  .note { font-size:12px; color:#d7b66b; word-break:break-word; }
  .actions { margin-top:auto; display:flex; gap:8px; }
  button { background:#232836; color:var(--txt); border:1px solid var(--line);
           border-radius:8px; padding:7px 12px; font-size:13px; cursor:pointer; }
  button:hover { border-color:#3a4254; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  button.danger { background:transparent; border-color:rgba(217,83,79,.5); color:#ff8b87; }
  button:disabled { opacity:.45; cursor:wait; }
  section { background:var(--card); border:1px solid var(--line); border-radius:12px;
            padding:16px; margin-bottom:16px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--muted); font-weight:600; font-size:11.5px; text-transform:uppercase; }
  tr:last-child td { border-bottom:none; }
  code,pre { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  pre { background:#0b0d11; border:1px solid var(--line); border-radius:8px;
        padding:12px; overflow:auto; max-height:260px; font-size:12px; }
  textarea { width:100%; min-height:260px; background:#0b0d11; color:var(--txt);
             border:1px solid var(--line); border-radius:8px; padding:12px;
             font-family:ui-monospace,monospace; font-size:12.5px; }
  .banner { background:rgba(215,182,107,.12); border:1px solid rgba(215,182,107,.4);
            color:#e8cd8b; padding:10px 14px; border-radius:10px; margin-bottom:16px; }
  .err { color:#ff8b87; font-size:12.5px; }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  @media (max-width:800px){ .grid2 { grid-template-columns:1fr; } }
  .switch { display:flex; gap:8px; align-items:center; color:var(--muted);
            font-size:12.5px; }
  a { color:var(--accent); }
  .gate { position:fixed; inset:0; background:rgba(0,0,0,.72); z-index:50;
          display:flex; align-items:center; justify-content:center; }
  .gatebox { background:var(--card); border:1px solid var(--line); border-radius:12px;
             padding:24px; width:340px; display:flex; flex-direction:column; gap:12px; }
  .gatebox input { background:#0b0d11; color:var(--txt); border:1px solid var(--line);
                   border-radius:8px; padding:9px; font-family:ui-monospace,monospace; }
</style></head>
<body>
<div id="gate" class="gate" style="display:none">
  <div class="gatebox">
    <h2 style="margin:0">Token de acesso</h2>
    <p class="muted" style="margin:0">Informe o token do painel
      (<code>/etc/vpn-split/ui.token</code>).</p>
    <input id="tok" type="password" placeholder="token" autocomplete="off">
    <button class="primary" onclick="setToken()">Entrar</button>
    <div class="err" id="gateerr"></div>
  </div>
</div>
<header>
  <h1>vpn-split</h1>
  <span class="muted" id="wifi">carregando…</span>
  <span class="muted" id="profile"></span>
  <span style="flex:1"></span>
  <label class="switch"><input type="checkbox" id="fb" onchange="setFallback(this.checked)"> fallback UDP (túneis via Mullvad)</label>
  <button onclick="act('profile-apply')">Reaplicar perfil</button>
  <button onclick="act('apply')">Aplicar</button>
</header>
<main>
  <div id="banner"></div>
  <div class="err" id="err"></div>
  <div class="cards" id="cards"></div>

  <div class="grid2">
    <section>
      <h2>Rotas administradas (main)</h2>
      <table><thead><tr><th>Prefixo</th><th>Via</th><th>Dev</th><th>Origem</th></tr></thead>
      <tbody id="routes"></tbody></table>
      <div id="fulltunnel"></div>
    </section>
    <section>
      <h2>Saúde</h2>
      <table><tbody id="health"></tbody></table>
      <div class="muted" id="dns" style="margin-top:10px"></div>
    </section>
  </div>

  <section>
    <h2>Configuração (/etc/vpn-split/config.toml)</h2>
    <details>
      <summary class="muted" style="cursor:pointer">mostrar / editar</summary>
      <textarea id="cfg" spellcheck="false"></textarea>
      <div style="margin-top:10px;display:flex;gap:8px">
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
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const getToken = () => localStorage.getItem('vpn-token') || '';

(function () {
  const q = new URLSearchParams(location.search);
  const t = q.get('token');
  if (t) { localStorage.setItem('vpn-token', t); history.replaceState(null, '', location.pathname); }
})();

function gateCheck() {
  if (getToken()) { $('gate').style.display = 'none'; return true; }
  $('gate').style.display = 'flex'; return false;
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
  let data; try { data = JSON.parse(txt); } catch { data = { error: txt }; }
  if (!r.ok) throw new Error(data.error || txt);
  return data;
}

async function act(action, extra = {}) {
  try {
    await api('/api/action', { method:'POST', headers:{'Content-Type':'application/json'},
                               body: JSON.stringify({ action, ...extra }) });
    $('err').textContent = '';
  } catch (e) { $('err').textContent = 'Erro: ' + e.message; }
  setTimeout(refresh, 1000);
}

async function ctl(target, up, btn) {
  if (btn) { btn.disabled = true; btn.textContent = up ? 'ligando…' : 'desligando…'; }
  const extra = { target, up };
  if (up && target.startsWith('pritunl:')) {
    const v = prompt('Senha/OTP do Pritunl (deixe vazio se a sessão ainda é válida):');
    if (v === null) { if (btn) { btn.disabled = false; btn.textContent = 'Ligar'; } return; }
    if (v) extra.pw = v;
  }
  await act('ctl', extra);
}

async function setFallback(on) { await act('fallback', { on }); }

function render(d) {
  $('wifi').textContent = `${d.wifi.iface} · gw ${d.wifi.gateway || '-'} · DNS ${d.wifi.dns.join(', ') || '-'}`;
  $('profile').textContent = `Perfil ${d.profile.name} · SSID '${d.profile.ssid}'`;
  $('fb').checked = !!d.fallback;

  $('banner').innerHTML = (d.netns.status || '').includes('NeedsLogin')
    ? '<div class="banner">NetBird H2O precisa de login: <code>sudo vpn-split netns-login</code> (uma vez)</div>'
    : '';

  $('cards').innerHTML = d.controls.map(c => `
    <div class="card ${c.active ? 'on' : ''}">
      <div class="row"><strong>${esc(c.name)}</strong>
        <span class="pill ${c.active ? 'pon' : 'poff'}">${c.active ? 'ligado' : 'desligado'}</span></div>
      <div class="muted">${esc(c.detail)}</div>
      ${c.note ? `<div class="note">${esc(c.note)}</div>` : ''}
      <div class="actions">
        ${c.active
          ? `<button class="danger" onclick="ctl('${esc(c.target)}', false, this)">Desligar</button>`
          : `<button class="primary" onclick="ctl('${esc(c.target)}', true, this)">Ligar</button>`}
      </div>
    </div>`).join('');

  $('routes').innerHTML = d.routes.length ? d.routes.map(r => `
    <tr><td><code>${esc(r.prefix)}</code></td><td>${esc(r.via || '-')}</td>
        <td><code>${esc(r.dev)}</code></td><td class="muted">${esc(r.source)}</td></tr>`).join('')
    : '<tr><td colspan="4" class="muted">nenhuma</td></tr>';

  $('fulltunnel').innerHTML = d.full_tunnel.length
    ? `<div class="note" style="color:#ff8b87;margin-top:10px">full-tunnel ativo: ${d.full_tunnel.map(r => esc(r.prefix + ' dev ' + r.dev)).join(', ')}</div>`
    : '';

  const mv = d.mullvad;
  $('health').innerHTML = `
    <tr><td>Mullvad</td><td>${mv.connected ? '<span class="pill pon">conectada</span>' : '<span class="pill poff">desligada</span>'}</td></tr>
    <tr><td>Exclusões nft</td><td>${mv.connected ? `${mv.nft_elements} prefixos · regra ${mv.nft_rule ? 'ok' : '<b style="color:#ff8b87">ausente</b>'}` : '-'}</td></tr>
    <tr><td>Docker</td><td>${d.docker.join(', ') || '-'}${d.docker_clash.length ? ' <b style="color:#ff8b87">conflito!</b>' : ''}</td></tr>
    <tr><td>Conflitos VPN</td><td>${d.conflicts.length ? esc(d.conflicts.join(' · ')) : 'nenhum'}</td></tr>
    <tr><td>NetBird H2O</td><td>${d.netns.exists ? 'netns ativo' : 'ausente'}</td></tr>
    <tr><td>Bypass Wi-Fi</td><td>${d.pins.count} IPs (${Object.entries(d.pins.kinds).map(([k,v]) => k + ': ' + v).join(' · ')})</td></tr>`;

  $('dns').textContent = 'DNS roteado: ' + Object.entries(d.dns).map(([k,v]) => `${k}: ${v.join(' ')}`).join(' | ');
}

async function refresh() {
  if (!gateCheck()) return;
  try {
    const d = await api('/api/status');
    render(d);
    $('err').textContent = '';
  } catch (e) { $('err').textContent = 'Erro ao atualizar: ' + e.message; }
  try {
    const l = await api('/api/log');
    $('log').textContent = l.log || '';
  } catch {}
}

async function loadCfg() {
  try {
    const c = await api('/api/config');
    $('cfg').value = c.text;
    $('cfgmsg').textContent = '';
  } catch (e) { $('cfgmsg').textContent = e.message; }
}

async function saveCfg() {
  try {
    await api('/api/config', { method:'POST', headers:{'Content-Type':'application/json'},
                               body: JSON.stringify({ text: $('cfg').value }) });
    $('cfgmsg').textContent = 'salvo e aplicado';
    setTimeout(refresh, 800);
  } catch (e) { $('cfgmsg').textContent = 'erro: ' + e.message; }
}

refresh(); loadCfg();
setInterval(refresh, 5000);
</script>
</body></html>
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
