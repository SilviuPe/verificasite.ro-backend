from __future__ import annotations

import re
from typing import Dict, Optional, List, Any

import httpx


# -------------------------------------------------
# Regex
# -------------------------------------------------

PLUGIN_PATH_RE = re.compile(
    r"/wp-content/plugins/(?P<slug>[a-z0-9\-]+)/",
    re.IGNORECASE
)

PLUGIN_VERSION_RE = re.compile(r"[?&]ver=([0-9a-zA-Z\.\-_]+)")

def detect_wp_plugins_from_html(html: str) -> Dict[str, Optional[str]]:

    plugins: Dict[str, Optional[str]] = {}

    if not html:
        return plugins

    # 1. Detectare slug-uri
    for m in PLUGIN_PATH_RE.finditer(html):
        slug = m.group("slug")
        plugins.setdefault(slug, None)

    # 2. Detectare versiuni (?ver=)
    for m in PLUGIN_VERSION_RE.finditer(html):
        version = m.group(1)

        # cautam contextul apropiat pentru a identifica pluginul
        context = html[max(0, m.start() - 200):m.start()]
        slug_match = PLUGIN_PATH_RE.search(context)

        if slug_match:
            slug = slug_match.group("slug")
            plugins[slug] = version

    return plugins


async def fetch_latest_wp_plugin_version(slug: str) -> Optional[str]:

    url = f"https://api.wordpress.org/plugins/info/1.0/{slug}.json"

    async with httpx.AsyncClient(timeout=12.0) as client:
        try:
            response = await client.post(url)
            if response.status_code != 200:
                return None

            data = response.json()
            return data.get("version")

        except Exception:
            return None


# -------------------------------------------------
# Functie principala de audit pluginuri
# -------------------------------------------------

async def analyze_wp_plugins(html: str) -> Dict[str, Any]:

    detected_plugins = detect_wp_plugins_from_html(html)

    plugins_out: List[Dict[str, Optional[str]]] = []

    for slug, current_version in detected_plugins.items():
        latest_version = await fetch_latest_wp_plugin_version(slug)

        plugins_out.append({
            "name": slug,
            "current_version": current_version,
            "latest_version": latest_version
        })

    return {
        "plugins": plugins_out,
        "source": "wordpress.org",
        "limitations": (
            "Latest version is available only for plugins published in the "
            "official WordPress Plugin Repository. Premium or custom plugins "
            "do not expose a public authoritative version source."
        )
    }
