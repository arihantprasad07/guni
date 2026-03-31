"""Dashboard/static page helpers."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles


DASHBOARD_DIR = Path(__file__).resolve().parents[2] / "dashboard"


def mount_dashboard_assets(app: FastAPI) -> None:
    if DASHBOARD_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")


def render_dashboard_page(name: str, fallback_html: str = "") -> HTMLResponse:
    html_path = DASHBOARD_DIR / name
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html(name))
    return HTMLResponse(content=fallback_html)


def _read_dashboard_html(name: str) -> str:
    html = (DASHBOARD_DIR / name).read_text(encoding="utf-8")
    return _decorate_dashboard_html(name, html)


def _decorate_dashboard_html(name: str, html: str) -> str:
    private_pages = {"owner.html", "portal.html"}
    if name in private_pages:
        return html

    shell = _site_shell_assets(name)
    html = html.replace("</head>", f"{shell['style']}</head>")
    html = html.replace("</body>", f"{shell['script']}</body>")
    return html


def _site_shell_assets(name: str) -> dict[str, str]:
    page_slug = name.replace(".html", "")
    nav_html = """
<nav class="g-nav g-shell-nav g-shell-nav-injected" id="g-shell-nav">
  <a class="g-logo" href="/">guni<em>.dev</em></a>
  <div class="g-nav-links">
    <a href="/">Home</a>
    <a href="/demo">Demo</a>
    <a href="/enterprise">Enterprise</a>
    <a href="/integrate">Integrate</a>
    <a href="/docs">Docs</a>
  </div>
  <div class="g-nav-right">
    <div class="g-shell-mini">
      <span class="g-shell-mini-dot"></span>
      <span>Production-grade agent security</span>
    </div>
    <a class="g-btn g-btn-ghost g-btn-sm" href="/signin">Sign in</a>
    <a class="g-btn g-btn-primary g-btn-sm" href="/signup">Start free</a>
  </div>
</nav>
""".strip()
    footer_html = """
<footer class="g-shell-footer" id="g-shell-footer">
  <div class="g-shell-footer-top">
    <div class="g-shell-brand">
      <div class="g-shell-brand-mark">guni</div>
      <div class="g-shell-brand-copy">Security infrastructure for browser agents, action-taking copilots, and adversarial web workflows.</div>
    </div>
    <div class="g-shell-footer-actions">
      <a class="g-btn g-btn-primary g-btn-sm" href="/signup">Start Free</a>
      <a class="g-btn g-btn-outline g-btn-sm" href="/demo">Live Demo</a>
    </div>
  </div>
  <div class="g-shell-footer-grid">
    <div class="g-shell-col">
      <div class="g-shell-col-title">Product</div>
      <a href="/demo">Demo</a>
      <a href="/integrate">Integrate</a>
      <a href="/docs">Docs</a>
      <a href="/portal">Portal</a>
    </div>
    <div class="g-shell-col">
      <div class="g-shell-col-title">Trust</div>
      <a href="/security">Security</a>
      <a href="/status">Status</a>
      <a href="/threats">Threat Feed</a>
      <a href="/privacy">Privacy</a>
      <a href="/terms">Terms</a>
      <a href="/about">About</a>
      <a href="/changelog">Changelog</a>
    </div>
    <div class="g-shell-col">
      <div class="g-shell-col-title">Commercial</div>
      <a href="/enterprise">Enterprise</a>
      <a href="/pilot">Pilot</a>
      <a href="mailto:hello@guni.dev">Contact</a>
      <a href="https://github.com/arihantprasad07/guni" target="_blank" rel="noreferrer">GitHub</a>
    </div>
  </div>
  <div class="g-shell-footer-bottom">
    <span>Built for real AI-agent production environments.</span>
    <span>&copy; 2026 Guni</span>
  </div>
</footer>
""".strip()

    style = """
<style id="g-shell-style">
.g-nav.g-shell-nav{box-shadow:0 18px 60px rgba(0,0,0,.22)}
.g-nav.g-shell-nav::after{content:'';position:absolute;left:0;right:0;bottom:-1px;height:1px;background:linear-gradient(90deg,transparent,rgba(245,166,35,.42),transparent)}
.g-shell-nav .g-nav-links a.is-active{color:var(--amber)}
.g-shell-nav .g-nav-links a.is-active::after{content:'';display:block;height:1px;background:var(--amber);margin-top:5px}
.g-shell-nav .g-nav-right{gap:10px}
.g-shell-nav-injected{position:sticky;top:0;z-index:20}
.g-shell-nav-injected + .auth-wrap{min-height:calc(100vh - 78px);padding-top:3rem}
.g-shell-nav-injected + .g-hero,.g-shell-nav-injected + .g-page-shell{padding-top:1rem}
.g-shell-mini{display:flex;align-items:center;gap:8px;padding:5px 10px;border:1px solid var(--border2);background:rgba(255,255,255,.02);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted2)}
.g-shell-mini-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 14px rgba(0,217,126,.55)}
.g-shell-footer{margin-top:4rem;padding:2.2rem var(--pad) 1.3rem;border-top:1px solid var(--border2);background:linear-gradient(180deg,rgba(255,255,255,0),rgba(255,255,255,.02))}
.g-shell-footer-top{max-width:var(--max);margin:0 auto 1.5rem;display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;flex-wrap:wrap}
.g-shell-brand{display:grid;gap:8px;max-width:520px}
.g-shell-brand-mark{font-family:var(--display);font-size:28px;font-weight:800;letter-spacing:-.04em;color:var(--amber)}
.g-shell-brand-copy{font-size:12px;color:var(--muted3);line-height:1.8}
.g-shell-footer-actions{display:flex;gap:10px;flex-wrap:wrap}
.g-shell-footer-grid{max-width:var(--max);margin:0 auto;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem;padding:1.25rem 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
.g-shell-col{display:grid;gap:7px}
.g-shell-col-title{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--amber)}
.g-shell-col a{font-size:12px;color:var(--muted3);text-decoration:none}
.g-shell-col a:hover{color:var(--amber)}
.g-shell-footer-bottom{max-width:var(--max);margin:1rem auto 0;display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;font-size:11px;color:var(--muted2)}
@media (max-width: 900px){.g-shell-nav-injected{padding-top:14px;padding-bottom:14px}.g-shell-nav-injected .g-nav-links{display:none}.g-shell-nav-injected .g-nav-right{margin-left:auto}}
@media (max-width: 720px){.g-shell-footer-grid{grid-template-columns:1fr}.g-shell-footer-bottom{flex-direction:column}.g-shell-nav-injected + .auth-wrap{padding-top:2rem}}
</style>
""".strip()

    script = f"""
<script id="g-shell-script">
(() => {{
  const page = {json.dumps(page_slug)};
  const isAuthPage = ['signin','signup','reset'].includes(page);
  let nav = document.querySelector('.g-nav');
  if (!nav) {{
    document.body.insertAdjacentHTML('afterbegin', {json.dumps(nav_html)});
    nav = document.querySelector('.g-nav');
  }}
  if (nav) {{
    nav.classList.add('g-shell-nav');
    const links = nav.querySelectorAll('.g-nav-links a');
    links.forEach((link) => {{
      const href = link.getAttribute('href') || '';
      if (!href || href.startsWith('#')) return;
      const normalized = href.replace(/\\/$/, '') || '/';
      const current = window.location.pathname.replace(/\\/$/, '') || '/';
      if (normalized === current) link.classList.add('is-active');
    }});
    const right = nav.querySelector('.g-nav-right');
    if (right && isAuthPage && !right.querySelector('.g-shell-mini')) {{
      const mini = document.createElement('div');
      mini.className = 'g-shell-mini';
      mini.innerHTML = '<span class="g-shell-mini-dot"></span><span>Hosted API + customer portal</span>';
      right.prepend(mini);
    }}
  }}

  let footer = document.querySelector('.g-footer, .g-shell-footer');
  if (!footer) {{
    document.body.insertAdjacentHTML('beforeend', {json.dumps(footer_html)});
    footer = document.querySelector('.g-shell-footer');
  }} else {{
    footer.innerHTML = {json.dumps(footer_html)}.replace(/^<footer[^>]*>/, '').replace(/<\\/footer>$/, '');
    if (!footer.classList.contains('g-shell-footer')) {{
      footer.classList.add('g-shell-footer');
    }}
    footer.id = 'g-shell-footer';
  }}
  if (footer && !footer.classList.contains('g-shell-footer')) {{
    footer.classList.add('g-shell-footer');
  }}
}})();
</script>
""".strip()
    return {"style": style, "script": script}
