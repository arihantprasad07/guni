"""Dashboard/static page helpers."""

from __future__ import annotations

import json
import re
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
    html = _apply_seo_metadata(name, html)
    if name in private_pages:
        return html

    shell = _site_shell_assets(name)
    html = _replace_last(html, "</head>", f"{shell['style']}</head>")
    html = _replace_last(html, "</body>", f"{shell['script']}</body>")
    return html


def _replace_last(source: str, needle: str, replacement: str) -> str:
    head, sep, tail = source.rpartition(needle)
    if not sep:
        return source
    return f"{head}{replacement}{tail}"


def _page_metadata(name: str) -> dict[str, str]:
    page = name.replace(".html", "")
    defaults = {
        "title": "Guni | AI Agent Security Middleware",
        "description": "Guni secures AI web agents against prompt injection, phishing, clickjacking, malicious redirects, and goal hijacking.",
        "image": "/static/favicon.svg",
    }
    per_page = {
        "landing": {
            "title": "Guni | Secure Your AI Agents",
            "description": "Protect AI web agents from prompt injection, phishing, clickjacking, and goal hijacking with Guni's security middleware.",
        },
        "index": {
            "title": "Guni Demo | Live AI Agent Threat Scan",
            "description": "Try the live Guni demo to scan pages for prompt injection, phishing, clickjacking, and other AI-agent threats.",
        },
        "signup": {
            "title": "Sign up | Guni",
            "description": "Create your Guni account, choose a plan, and start protecting AI agents with hosted scanning and dashboard access.",
        },
        "signin": {
            "title": "Sign in | Guni",
            "description": "Sign in to the Guni portal to manage scans, alerts, billing, and API keys for your AI agents.",
        },
        "portal": {
            "title": "Customer Portal | Guni",
            "description": "Manage API keys, usage, billing, alerts, and scan history from the Guni customer portal.",
        },
        "pilot": {
            "title": "Pilot Program | Guni",
            "description": "Request a focused Guni pilot for high-risk browser workflows and autonomous web-agent evaluations.",
        },
        "enterprise": {
            "title": "Enterprise | Guni",
            "description": "Evaluate Guni for production AI-agent security, hosted scanning, trust workflows, and enterprise rollout planning.",
        },
        "docs": {
            "title": "Docs | Guni",
            "description": "Integrate Guni into browser agents, Playwright flows, and web automation stacks with hosted or self-hosted options.",
        },
        "integrate": {
            "title": "Integrate | Guni",
            "description": "Learn how to add Guni to your AI web agent stack and protect live browser workflows in production.",
        },
        "threats": {
            "title": "Threat Feed | Guni",
            "description": "Monitor the Guni threat feed to see live scans, blocked threats, and platform-wide AI-agent attack trends.",
        },
    }
    return {**defaults, **per_page.get(page, {})}


def _upsert_meta(html: str, attr: str, value: str, *, property_attr: bool = False) -> str:
    key = "property" if property_attr else "name"
    pattern = rf'<meta\s+{key}="{re.escape(attr)}"\s+content="[^"]*"\s*/?>'
    tag = f'<meta {key}="{attr}" content="{value}"/>'
    if re.search(pattern, html, flags=re.IGNORECASE):
        return re.sub(pattern, tag, html, count=1, flags=re.IGNORECASE)
    return _replace_last(html, "</head>", f"{tag}\n</head>")


def _replace_title(html: str, title: str) -> str:
    if re.search(r"<title>.*?</title>", html, flags=re.IGNORECASE | re.DOTALL):
        return re.sub(r"<title>.*?</title>", f"<title>{title}</title>", html, count=1, flags=re.IGNORECASE | re.DOTALL)
    return html


def _apply_seo_metadata(name: str, html: str) -> str:
    metadata = _page_metadata(name)
    html = _replace_title(html, metadata["title"])
    html = _upsert_meta(html, "description", metadata["description"])
    html = _upsert_meta(html, "og:title", metadata["title"], property_attr=True)
    html = _upsert_meta(html, "og:description", metadata["description"], property_attr=True)
    html = _upsert_meta(html, "og:image", metadata["image"], property_attr=True)
    html = _upsert_meta(html, "twitter:card", "summary_large_image")
    html = _upsert_meta(html, "twitter:title", metadata["title"])
    html = _upsert_meta(html, "twitter:description", metadata["description"])
    html = _upsert_meta(html, "twitter:image", metadata["image"])
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
