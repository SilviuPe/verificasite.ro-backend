from __future__ import annotations

import asyncio
import json
import re
import socket
import uuid
import io
import httpx

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime, timedelta
from openpyxl import Workbook
from jose import jwt

from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import Depends, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import StreamingResponse



from screenshots import take_screenshots_base64
from utils import _get_ssl_info
from database.database import AuditDatabase

DATABASE_URL = "postgresql+psycopg2://verificasite:verificasite_admin@localhost:5432/verificasite_db"
app = FastAPI(title="Site Analyzer", version="1.0.0")

app.mount("/screenshots", StaticFiles(directory="screenshots"), name="screenshots")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:4173", "http://51.38.65.188"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

SECRET_KEY = "verificasiteAdmin"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def admin_required(user=Depends(get_current_user)):
    if not user.get("admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

LANGUAGE_CODE_TO_NAME = {
    "en": "Engleza",
    "fr": "Franceza",
    "ro": "Romana",
    "de": "Germana",
    "es": "Spaniola",
    "it": "Italiana",
    "pt": "Portugheza",
    "nl": "Olandeza",
    "sv": "Suedeza",
    "da": "Daneza",
    "fi": "Finlandeza",
    "no": "Norvegiana",
    "pl": "Poloneza",
    "cs": "Ceha",
    "sk": "Slovaca",
    "hu": "Maghiara",
    "bg": "Bulgara",
    "el": "Greaca",
    "tr": "Turca",
    "ru": "Rusa",
    "uk": "Ucraineana",
    "zh": "Chineza",
    "ja": "Japoneza",
    "ko": "Coreeana",
}

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="URL in orice forma: domain, www.domain, http(s)://...")
    device: int = Field(1, ge=1, le=2)

class AnalyzeResponse(BaseModel):
    input_url: str
    normalized_candidates: List[str]
    fetched_url: str
    final_url: str
    redirect_chain: List[str]
    status_code: int
    ip_address: Optional[str]

    seo: Dict[str, Any]
    structured_data: Dict[str, Any]
    social: Dict[str, Any]
    tech: Dict[str, Any]
    checks: Dict[str, Any]
    screenshots: Dict[str, str]


def _clean_input(raw: str) -> str:
    s = (raw or "").strip()
    # elimina spatii interne accidentale
    s = re.sub(r"\s+", "", s)
    return s


def _build_url_candidates(raw: str) -> List[str]:
    """
    Accepta:
      silvyu.dev
      www.silvyu.dev
      https://www.silvyu.dev
      https://silvyu.dev
    Returneaza o lista de candidate in ordinea probarii.
    Strategia:
      - daca are schema, il folosim primul
      - altfel incercam https:// apoi http://
    """
    raw = _clean_input(raw)
    if not raw:
        return []

    parsed = urlparse(raw)
    candidates: List[str] = []

    if parsed.scheme in ("http", "https"):
        # deja e URL complet
        candidates.append(raw)
    else:
        # domain/path fara schema
        # daca user a introdus ceva de genul "example.com/path"
        candidates.append(f"https://{raw}")
        candidates.append(f"http://{raw}")

    # dedup pastrand ordinea
    out: List[str] = []
    seen = set()
    for c in candidates:
        if c not in seen:
            out.append(c)
            seen.add(c)
    return out


def _hostname_from_url(u: str) -> Optional[str]:
    try:
        p = urlparse(u)
        return p.hostname
    except Exception:
        return None


def _resolve_ip(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


@dataclass
class FetchResult:
    fetched_url: str
    final_url: str
    status_code: int
    redirect_chain: List[str]
    html: str
    headers: Dict[str, str]


async def _fetch_first_working(candidates: List[str], timeout_s: float = 25.0) -> FetchResult:
    """
    Incearca candidatele in ordine. Pentru fiecare:
      - GET cu follow_redirects=True
      - verify TLS activ (default)
    Daca https pica (ex: fara SSL), va merge pe http candidate.
    """
    if not candidates:
        raise HTTPException(status_code=400, detail="Empty URL")

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(timeout_s),
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; SiteAnalyzer/1.0; +https://example.local)"
        },
    ) as client:
        last_exc: Optional[str] = None
        for c in candidates:
            try:
                r = await client.get(c)
                chain = [str(h.url) for h in r.history] + [str(r.url)]
                html = r.text or ""
                headers = {k.lower(): v for k, v in r.headers.items()}
                return FetchResult(
                    fetched_url=c,
                    final_url=str(r.url),
                    status_code=int(r.status_code),
                    redirect_chain=chain,
                    html=html,
                    headers=headers,
                )
            except httpx.HTTPError as e:
                last_exc = str(e)
                continue

    raise HTTPException(
        status_code=502,
        detail=f"Could not fetch URL with provided candidates. Last error: {last_exc}",
    )


def _text_len(s: str) -> int:
    return len((s or "").strip())

def _detect_google_ads(html: str) -> Dict[str, Any]:
    html_lower = (html or "").lower()

    aw_ids = set()
    conversion_ids = set()
    signals = []

    # 1. Scripturi Google Ads
    if "googleadservices.com" in html_lower:
        signals.append("googleadservices_script")

    # 2. gtag cu AW
    for m in re.findall(r"aw-\d{6,}", html_lower, re.I):
        aw_ids.add(m.upper())
        signals.append("gtag_aw_config")

    # 3. Conversii Google Ads
    # send_to: "AW-XXXX/YYYY"
    for m in re.findall(r'aw-\d+/\w+', html_lower, re.I):
        conversion_ids.add(m.upper())
        signals.append("conversion_event")

    is_present = len(aw_ids) > 0 or len(conversion_ids) > 0 or len(signals) > 0

    return {
        "present": is_present,
        "aw_ids": sorted(list(aw_ids)),
        "conversion_ids": sorted(list(conversion_ids)),
        "signals": list(dict.fromkeys(signals)),
        "note": (
            "Google Ads tracking detected via public page code (AW IDs / conversion tags). "
            "Account ownership, budgets and campaigns cannot be determined."
            if is_present
            else "No Google Ads tracking signals detected in page HTML."
        ),
    }


def _detect_facebook_pixel(html: str) -> Dict[str, Any]:
    html_lower = (html or "").lower()

    signals = []

    # 1. Script oficial Meta
    if "connect.facebook.net" in html_lower:
        signals.append("connect_facebook_net")

    # 2. fbq init / track
    if "fbq('init'" in html_lower or 'fbq("init"' in html_lower:
        signals.append("fbq_init")

    if "fbq('track'" in html_lower or 'fbq("track"' in html_lower:
        signals.append("fbq_track")

    # 3. Noscript image fallback
    if "facebook.com/tr" in html_lower:
        signals.append("facebook_tr_pixel")

    is_present = len(signals) > 0

    return {
        "present": is_present,
        "signals": signals,
        "note": (
            "Meta (Facebook) Pixel detected via standard implementation signals."
            if is_present
            else "No Meta (Facebook) Pixel signals detected in page HTML."
        ),
    }

def _detect_language(html: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html or "", "lxml")

    detected_code = None
    source = None

    # 1. <html lang="...">
    html_tag = soup.find("html")
    if html_tag and html_tag.get("lang"):
        detected_code = str(html_tag.get("lang")).strip()
        source = "html_lang_attribute"

    # 2. OpenGraph og:locale
    if not detected_code:
        og_locale = soup.find("meta", attrs={"property": re.compile(r"^og:locale$", re.I)})
        if og_locale and og_locale.get("content"):
            detected_code = str(og_locale.get("content")).strip()
            source = "opengraph_locale"

    # 3. Meta Content-Language
    if not detected_code:
        meta_lang = soup.find(
            "meta",
            attrs={"http-equiv": re.compile(r"^content-language$", re.I)},
        )
        if meta_lang and meta_lang.get("content"):
            detected_code = str(meta_lang.get("content")).strip()
            source = "meta_content_language"

    if not detected_code:
        return {
            "detected": False,
            "language": None,
            "language_code": None,
            "source": None,
            "note": "No explicit language declaration found.",
        }

    # normalizare BCP 47: en-US -> en
    primary_code = detected_code.split("-")[0].lower()

    language_name = LANGUAGE_CODE_TO_NAME.get(primary_code)

    return {
        "detected": True,
        "language": language_name,          # ex: "Engleza"
        "language_code": detected_code.lower(),  # ex: "en-us"
        "source": source,
        "note": (
            None
            if language_name
            else "Language code detected, but no human-readable mapping is defined."
        ),
    }

def _detect_google_maps(html: str) -> bool:
    s = (html or "").lower()

    signals = [
        "google.com/maps",
        "maps.google.com",
        "goo.gl/maps",
        "maps/embed",
        "pb=!1m",           # pattern tipic embed
        "googleapis.com/maps",
    ]

    for sig in signals:
        if sig in s:
            return True

    return False


def _extract_social_links(base_url: str, html: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html or "", "lxml")

    social_domains = {
        "facebook": ["facebook.com", "fb.com"],
        "instagram": ["instagram.com"],
    }

    found: Dict[str, List[str]] = {
        "facebook": [],
        "instagram": [],
    }

    for a in soup.find_all("a"):
        href = a.get("href")
        if not href:
            continue

        href = str(href).strip()
        if href.startswith("#"):
            continue

        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        host = (parsed.hostname or "").lower()

        for platform, domains in social_domains.items():
            for d in domains:
                if host.endswith(d):
                    found[platform].append(full_url)

    for k in found:
        found[k] = list(dict.fromkeys(found[k]))[:10]

    return {
        "facebook": {
            "present": len(found["facebook"]) > 0,
            "links": found["facebook"],
        },
        "instagram": {
            "present": len(found["instagram"]) > 0,
            "links": found["instagram"],
        },
        "note": "Links are extracted only from explicit anchor tags. No inference is performed.",
    }


def _analyze_html(base_url: str, html: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html or "", "lxml")

    # Title
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""

    # Meta description
    meta_desc = ""
    md = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    if md and md.get("content"):
        meta_desc = str(md.get("content")).strip()

    # Headings
    headings: Dict[str, int] = {}
    for lvl in range(1, 7):
        headings[f"h{lvl}"] = len(soup.find_all(f"h{lvl}"))

    # Images alt
    images = soup.find_all("img")
    total_imgs = len(images)
    missing_alt = 0
    for img in images:
        alt = img.get("alt")
        if alt is None or str(alt).strip() == "":
            missing_alt += 1

    # Extract links (for broken link test)
    raw_links: List[str] = []
    for a in soup.find_all("a"):
        href = a.get("href")
        if not href:
            continue
        href = str(href).strip()
        if href.startswith("#"):
            continue
        if href.lower().startswith(("mailto:", "tel:", "javascript:")):
            continue
        raw_links.append(urljoin(base_url, href))

    # Favicon
    favicon_links = []
    for rel in ("icon", "shortcut icon", "apple-touch-icon"):
        for tag in soup.find_all("link", rel=lambda x: x and rel in str(x).lower()):
            href = tag.get("href")
            if href:
                favicon_links.append(urljoin(base_url, str(href).strip()))
    favicon_links = list(dict.fromkeys(favicon_links))  # dedup order

    # Mobile viewport heuristic
    viewport_ok = False
    vp = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
    if vp and vp.get("content"):
        viewport_ok = True

    # Schema.org JSON-LD
    jsonld_count = 0
    jsonld_samples: List[Any] = []
    for tag in soup.find_all("script", attrs={"type": re.compile(r"application/ld\+json", re.I)}):
        txt = tag.get_text(strip=True)
        if not txt:
            continue
        jsonld_count += 1
        # incearca parse, dar nu pica daca e invalid
        try:
            obj = json.loads(txt)
            if len(jsonld_samples) < 2:
                jsonld_samples.append(obj)
        except Exception:
            pass

    # OpenGraph
    og_tags = soup.find_all("meta", attrs={"property": re.compile(r"^og:", re.I)})
    og_present = len(og_tags) > 0

    return {
        "title": {"value": title, "length": _text_len(title)},
        "meta_description": {"value": meta_desc, "length": _text_len(meta_desc)},
        "headings": headings,
        "images": {
            "total": total_imgs,
            "missing_alt": missing_alt,
        },
        "links": {
            "extracted_total": len(raw_links),
            "extracted_sample": raw_links[:25],
        },
        "favicon": {
            "declared_icons": favicon_links[:10],
            "has_declared_icon": len(favicon_links) > 0,
        },
        "mobile": {
            "has_viewport_meta": viewport_ok,
        },
        "structured_data": {
            "jsonld_blocks": jsonld_count,
            "jsonld_samples": jsonld_samples,
        },
        "opengraph": {
            "present": og_present,
            "count": len(og_tags),
        },
    }


async def _check_links(links: List[str], limit: int = 60) -> Dict[str, Any]:
    """
    Verifica linkurile cu HEAD (fallback GET). Limitam la primele N ca sa nu explodeze timpul.
    """
    links = links[:limit]
    sem = asyncio.Semaphore(12)

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        headers={"User-Agent": "Mozilla/5.0 (compatible; SiteAnalyzer/1.0; +https://example.local)"},
    ) as client:

        async def check_one(u: str) -> Tuple[str, Optional[int], Optional[str]]:
            async with sem:
                try:
                    # Unele servere nu suporta HEAD corect
                    try:
                        r = await client.head(u)
                        return (u, int(r.status_code), None)
                    except httpx.HTTPError:
                        r = await client.get(u)
                        return (u, int(r.status_code), None)
                except Exception as e:
                    return (u, None, str(e))

        results = await asyncio.gather(*(check_one(u) for u in links))

    broken = []
    ok = 0
    for u, code, err in results:
        if err is not None or code is None or code >= 400:
            broken.append({"url": u, "status_code": code, "error": err})
        else:
            ok += 1

    return {
        "checked": len(results),
        "ok": ok,
        "broken": len(broken),
        "broken_samples": broken[:25],
        "note": f"Checked first {len(results)} links (cap {limit}).",
    }


async def _fetch_text(url: str) -> Tuple[bool, Optional[str], Optional[int]]:
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        headers={"User-Agent": "Mozilla/5.0 (compatible; SiteAnalyzer/1.0; +https://example.local)"},
    ) as client:
        try:
            r = await client.get(url)
            if r.status_code < 400:
                return True, (r.text or ""), int(r.status_code)
            return False, None, int(r.status_code)
        except Exception:
            return False, None, None


async def _www_resolve_report(final_url: str) -> Dict[str, Any]:
    """
    Verifica daca www -> non-www (sau invers) se redirectioneaza.
    Folosim allow_redirects=False ca sa vedem status 301/302.
    """
    p = urlparse(final_url)
    if not p.hostname:
        return {"supported": False}

    host = p.hostname
    scheme = p.scheme or "https"
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"

    if host.startswith("www."):
        non = host[len("www.") :]
        www = host
    else:
        non = host
        www = "www." + host

    non_url = f"{scheme}://{non}{path}"
    www_url = f"{scheme}://{www}{path}"

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(12.0),
        headers={"User-Agent": "Mozilla/5.0 (compatible; SiteAnalyzer/1.0; +https://example.local)"},
    ) as client:
        out: Dict[str, Any] = {"supported": True, "non_www": non_url, "www": www_url}
        try:
            r1 = await client.get(www_url)
            out["www_status"] = int(r1.status_code)
            out["www_location"] = r1.headers.get("location")
        except Exception as e:
            out["www_error"] = str(e)

        try:
            r2 = await client.get(non_url)
            out["non_www_status"] = int(r2.status_code)
            out["non_www_location"] = r2.headers.get("location")
        except Exception as e:
            out["non_www_error"] = str(e)

    return out


def _detect_tech(html: str) -> Dict[str, Any]:
    s = (html or "").lower()

    def has(*patterns):
        return any(p in s for p in patterns)

    tech = {
        # Google ecosystem
        "google_analytics": has(
            "www.googletagmanager.com/gtag/js",
            "google-analytics.com/analytics.js",
            "gtag(",
            "ga(",
        ),

        "google_tag_manager": has(
            "googletagmanager.com/gtm.js",
            "gtm.start",
            "gtm-",
        ),

        "google_fonts": has(
            "fonts.googleapis.com",
            "fonts.gstatic.com",
            "googleapis.com/css2",
        ),

        "google_maps": has(
            "google.com/maps",
            "maps.google.com",
            "goo.gl/maps",
            "maps/embed",
            "pb=!1m",
            "googleapis.com/maps",
        ),

        # Marketing and tracking
        "facebook_pixel": has(
            "connect.facebook.net",
            "fbq(",
            "facebook.com/tr",
        ),

        "hotjar": has(
            "static.hotjar.com",
            "hotjar-",
            "hjSettings",
        ),

        # Infrastructure
        "cloudflare": has(
            "cloudflare.com",
            "cf-ray",
            "__cf_chl",
        ),

        # UX and media
        "recaptcha": has(
            "google.com/recaptcha",
            "g-recaptcha",
        ),

        "youtube_embed": has(
            "youtube.com/embed",
            "youtu.be",
        ),

        # Libraries
        "jquery": has(
            "jquery",
            "jquery.min.js",
        ),

        # Cookie consent
        "cookie_consent": has(
            "cookieconsent",
            "onetrust",
            "cookielaw",
            "iubenda",
            "termly",
        ),
    }

    tech["note"] = (
        "Detection is based strictly on HTML signals and known script patterns. "
        "Results represent presence indicators, not configuration correctness."
    )

    return tech


async def _custom_404_check(final_url: str) -> Dict[str, Any]:
    """
    Request un path random. Daca primim 404, probabil exista 404 handling.
    Nu putem sti sigur daca e 'custom' fara reguli specifice, dar raportam semnale.
    """
    p = urlparse(final_url)
    base = f"{p.scheme}://{p.netloc}"
    rnd = uuid.uuid4().hex
    probe = f"{base}/__not_found_probe__{rnd}"

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(12.0),
        headers={"User-Agent": "Mozilla/5.0 (compatible; SiteAnalyzer/1.0; +https://example.local)"},
    ) as client:
        try:
            r = await client.get(probe)
            body_len = len(r.text or "")
            return {
                "probe_url": probe,
                "status_code": int(r.status_code),
                "body_length": body_len,
                "has_404": int(r.status_code) == 404,
            }
        except Exception as e:
            return {"probe_url": probe, "error": str(e)}


def _extract_wp_version_from_text(text: str) -> Optional[str]:
    """
    Extrage o versiune WordPress dintr-un text de tip generator.
    Accepta doar formate clasice: 'WordPress 6.5.3'
    """
    if not text:
        return None
    m = re.search(r"\bWordPress\s+(\d+(?:\.\d+){1,3})\b", text, re.IGNORECASE)
    return m.group(1) if m else None


def _detect_wordpress_from_html(html: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Detectie WordPress bazata pe semnale verificabile din HTML si headers.
    Nu ghicim. Daca versiunea nu este expusa, returnam null si motiv.
    """
    soup = BeautifulSoup(html or "", "lxml")
    html_lower = (html or "").lower()

    signals: List[str] = []
    version: Optional[str] = None

    # 1) Meta generator
    gen = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    if gen and gen.get("content"):
        gen_content = str(gen.get("content")).strip()
        if "wordpress" in gen_content.lower():
            signals.append("meta_generator")
            v = _extract_wp_version_from_text(gen_content)
            if v:
                version = v

    # 2) Prezenta de path-uri specifice
    if "/wp-content/" in html_lower:
        signals.append("wp_content_path")
    if "/wp-includes/" in html_lower:
        signals.append("wp_includes_path")

    # 3) Headers (rare)
    x_powered = (headers.get("x-powered-by") or "").lower()
    if "wordpress" in x_powered:
        signals.append("x_powered_by")

    link_hdr = (headers.get("link") or "").lower()
    # uneori apare rel="https://api.w.org/"
    if "api.w.org" in link_hdr:
        signals.append("header_api_w_org")

    is_wordpress = len(signals) > 0

    reason: Optional[str] = None
    if is_wordpress and not version:
        reason = "WordPress detected, but version is not exposed via meta generator or other public hints."

    return {
        "is_wordpress": is_wordpress,
        "version": version,          # poate fi None
        "signals": signals,          # ca sa vezi pe ce s-a bazat
        "version_reason": reason,    # explicatie cand e None
    }

async def _try_wp_version_from_feed(final_url: str) -> Optional[str]:
    """
    Incearca /feed/ sau /?feed=rss2 si cauta generator.
    Returneaza versiune doar daca gaseste explicit 'WordPress x.y.z'.
    """
    candidates = [
        urljoin(final_url, "/feed/"),
        urljoin(final_url, "/?feed=rss2"),
    ]

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(12.0),
        headers={"User-Agent": "Mozilla/5.0 (compatible; SiteAnalyzer/1.0; +https://example.local)"},
    ) as client:
        for u in candidates:
            try:
                r = await client.get(u)
                if r.status_code >= 400:
                    continue
                txt = r.text or ""
                # cauta <generator>https://wordpress.org/?v=6.5.3</generator>
                m = re.search(r"wordpress\.org/\?v=(\d+(?:\.\d+){1,3})", txt, re.IGNORECASE)
                if m:
                    return m.group(1)
                # sau generator "WordPress 6.5.3"
                v = _extract_wp_version_from_text(txt)
                if v:
                    return v
            except Exception:
                continue
    return None

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    candidates = _build_url_candidates(req.url)
    if not candidates:
        raise HTTPException(status_code=400, detail="Invalid URL input")

    audit_db = AuditDatabase(DATABASE_URL)

    fetched = await _fetch_first_working(candidates)
    host = _hostname_from_url(fetched.final_url)
    ip = _resolve_ip(host)
    screenshots_b64 = await take_screenshots_base64(fetched.final_url)
    ssl_info = _get_ssl_info(fetched.final_url)

    html_analysis = _analyze_html(fetched.final_url, fetched.html)
    social_links = _extract_social_links(fetched.final_url, fetched.html)
    language = _detect_language(fetched.html)
    wp = _detect_wordpress_from_html(fetched.html, fetched.headers)
    facebook_pixel = _detect_facebook_pixel(fetched.html)
    google_ads = _detect_google_ads(fetched.html)
    # optional: daca e wordpress dar versiunea lipseste, incearca feed
    if wp["is_wordpress"] and not wp["version"]:
        feed_v = await _try_wp_version_from_feed(fetched.final_url)
        if feed_v:
            wp["version"] = feed_v
            wp["signals"].append("rss_generator")
            wp["version_reason"] = None

    links_sample = html_analysis["links"]["extracted_sample"]

    links_task = asyncio.create_task(_check_links(links_sample, limit=60))

    robots_url = urljoin(fetched.final_url, "/robots.txt")
    sitemap_url = urljoin(fetched.final_url, "/sitemap.xml")

    robots_task = asyncio.create_task(_fetch_text(robots_url))
    sitemap_task = asyncio.create_task(_fetch_text(sitemap_url))
    www_task = asyncio.create_task(_www_resolve_report(fetched.final_url))
    custom404_task = asyncio.create_task(_custom_404_check(fetched.final_url))

    links_report = await links_task
    robots_ok, robots_text, robots_status = await robots_task
    sitemap_ok, sitemap_text, sitemap_status = await sitemap_task
    www_report = await www_task
    custom404_report = await custom404_task

    sitemap_from_robots: List[str] = []
    if robots_ok and robots_text:
        for line in robots_text.splitlines():
            if line.lower().startswith("sitemap:"):
                v = line.split(":", 1)[1].strip()
                if v:
                    sitemap_from_robots.append(v)

    tech = _detect_tech(fetched.html)
    tech["wordpress"] = wp
    tech["facebook_pixel"] = facebook_pixel
    tech["google_ads"] = google_ads
    tech["google_maps"] = _detect_google_maps(fetched.html)
    seo = {
        "title": html_analysis["title"],
        "meta_description": html_analysis["meta_description"],
        "google_snippet_preview": {
            "title": html_analysis["title"]["value"],
            "url": fetched.final_url,
            "description": html_analysis["meta_description"]["value"],
        },
        "headings": html_analysis["headings"],
        "images": html_analysis["images"],
        "links": {
            "broken_links": links_report,
        },
        "www_resolve": www_report,
        "robots_txt": {
            "url": robots_url,
            "present": bool(robots_ok),
            "status_code": robots_status,
            "sitemap_lines": sitemap_from_robots[:10],
        },
        "sitemap": {
            "url": sitemap_url,
            "present": bool(sitemap_ok),
            "status_code": sitemap_status,
        },
        "mobile": html_analysis["mobile"],
        "favicon": html_analysis["favicon"],
        "custom_404": custom404_report,
    }

    structured_data = {
        "schema_org_jsonld": html_analysis["structured_data"],
    }

    social = {
        "opengraph": html_analysis["opengraph"],
        "profiles": social_links,
        "language": language,
    }

    checks = {
        "fetch": {
            "fetched_url": fetched.fetched_url,
            "final_url": fetched.final_url,
            "status_code": fetched.status_code,
            "redirect_chain": fetched.redirect_chain,
        },
        "ssl_certificate": ssl_info,
    }
    device = req.device

    audit_result = audit_db.insert_audit(
        ip=ip,
        url=fetched.final_url,
        html=fetched.html,
        scor=100,
        device=device
    )

    if audit_result["status"] != 200:
        print(audit_result["message"])

    return AnalyzeResponse(
        input_url=req.url,
        normalized_candidates=candidates,
        fetched_url=fetched.fetched_url,
        final_url=fetched.final_url,
        redirect_chain=fetched.redirect_chain,
        status_code=fetched.status_code,
        ip_address=ip,
        seo=seo,
        structured_data=structured_data,
        social=social,
        tech=tech,
        checks=checks,
        screenshots=screenshots_b64,
    )


@app.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest):

    db_instance = AuditDatabase(database_url=DATABASE_URL)

    result = db_instance.authenticate(req.username, req.password)
    print(result["message"])
    if result["status"] != 200:
        raise HTTPException(status_code=401, detail=result["message"])

    token = create_access_token(
        {
            "sub": result["data"]["username"],
            "admin": result["data"]["admin"],
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@app.get("/admin-only")
async def admin_endpoint(user=Depends(admin_required)):
    return {"ok": True}


@app.get("/allaudits")
async def get_all_audits(user=Depends(admin_required)):
    """
    Returneaza toate audit-urile din baza de date. Acces doar pentru admin.
    """
    audit_db = AuditDatabase(DATABASE_URL)
    result = audit_db.get_audits()

    returned_result = []
    for audit in result["data"]:
        new_audit_entity = audit
        new_audit_entity["html"] = audit["html"][:100]
        returned_result.append(new_audit_entity)

    if result["status"] != 200:
        raise HTTPException(status_code=500, detail="Failed to fetch audits")

    return {"audits": returned_result}


@app.post("/export_xlsx")
async def get_export_xlsx_by_ids(
    ids: List[int] = Query(...),  # lista de ID-uri
    user=Depends(admin_required)
):
    audit_db = AuditDatabase(DATABASE_URL)

    # Preluam audit-urile filtrate doar dupa ID-uri
    all_audits = []
    for audit_id in ids:
        result = audit_db.get_audits(id=audit_id)
        if result.get("status") == 200:
            all_audits.extend(result["data"])

    if not all_audits:
        return {"status": 404, "message": "No audits found for provided IDs"}

    # Cream fisierul XLSX
    wb = Workbook()
    ws = wb.active
    ws.title = "Audits"

    # Header
    headers = ["ID", "IP", "URL", "HTML", "Scor", "Device", "Date"]
    ws.append(headers)

    # Continut
    for a in all_audits:
        ws.append([
            a["id"],
            a["ip"],
            a["url"],
            a["html"],
            a["scor"],
            "Desktop" if a["device"] == 1 else "Mobile",
            a["date"]
        ])

    # Scriem XLSX intr-un buffer
    file_stream = io.BytesIO()
    wb.save(file_stream)
    file_stream.seek(0)

    filename = f"audits_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    # Returnam ca download
    return StreamingResponse(
        file_stream,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.post("/export_pdf")
async def get_export_pdf(
    ids: List[int] = Query(...),
    user=Depends(admin_required)
):
    audit_db = AuditDatabase(DATABASE_URL)

    all_audits = []
    for audit_id in ids:
        result = audit_db.get_audits(id=audit_id)
        if result.get("status") == 200:
            all_audits.extend(result["data"])

    if not all_audits:
        return {"status": 404, "message": "No audits found for provided IDs"}

    # Setari PDF
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Margin
    margin_left = 20 * mm
    margin_top = height - 20 * mm
    line_height = 8 * mm
    max_rows_per_page = int((height - 40*mm) / line_height)  # 20mm top + 20mm bottom

    # Functie pentru desenarea headerului
    def draw_header(page_num: int):
        c.setFont("Helvetica-Bold", 12)
        header_text = "Audits Export - Page %d" % page_num
        c.drawString(margin_left, height - 15*mm, header_text)
        c.setFont("Helvetica-Bold", 10)
        columns = ["ID", "IP", "URL", "Scor", "Device", "Data"]
        x = margin_left
        c.drawString(x, height - 25*mm, columns[0][:20])  # limitam lungimea textului
        x += 10 * mm
        for col in columns[1:]:
            if col == 'URL':
                c.drawString(x, height - 25 * mm, col)
                x += 45 * mm
                continue

            c.drawString(x, height - 25*mm, col)
            x += 25*mm  # ajustati dupa nevoie

    # Desenam randurile
    y = margin_top
    row_count = 0
    page_num = 1
    draw_header(page_num)
    y -= 10*mm

    for audit in all_audits:
        if row_count >= max_rows_per_page:
            c.showPage()
            page_num += 1
            draw_header(page_num)
            y = margin_top - 10*mm
            row_count = 0

        c.setFont("Helvetica", 9)
        x = margin_left
        values = [
            str(audit["id"]),
            audit["ip"],
            audit["url"],
            str(audit["scor"]),
            "Desktop" if audit["device"] == 1 else "Mobile",
            audit["date"]
        ]

        c.drawString(x, y, values[0][:20])  # limitam lungimea textului
        x += 10 * mm

        for val in values[1:]:
            if values.index(val) == 2:
                c.drawString(x, y, val[:30])  # limitam lungimea textului
                x += 45*mm
                continue

            c.drawString(x, y, val[:20])  # limitam lungimea textului
            x += 25*mm
        y -= line_height
        row_count += 1

    c.save()
    buffer.seek(0)

    filename = f"audits_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
