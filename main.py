from __future__ import annotations

import asyncio
import json
import re
import socket
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(title="Site Analyzer", version="1.0.0")


class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="URL in orice forma: domain, www.domain, http(s)://...")


class AnalyzeResponse(BaseModel):
    input_url: str
    normalized_candidates: List[str]
    fetched_url: str
    final_url: str
    redirect_chain: List[str]
    status_code: int
    ip_address: Optional[str]

    # True daca final_url e https si requestul a reusit cu verify TLS
    ssl_ok: bool

    seo: Dict[str, Any]
    structured_data: Dict[str, Any]
    social: Dict[str, Any]
    tech: Dict[str, Any]
    checks: Dict[str, Any]


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

    # Heuristici simple. Nu sunt perfecte.
    ga = ("www.googletagmanager.com/gtag/js" in s) or ("google-analytics.com" in s) or ("gtag(" in s)
    gtm = ("googletagmanager.com/gtm.js" in s) or ("gtm-" in s)
    jquery = ("jquery" in s)

    return {
        "google_analytics_detected": bool(ga),
        "google_tag_manager_detected": bool(gtm),
        "jquery_detected": bool(jquery),
        "note": "Heuristic detection based on page HTML. False positives/negatives are possible.",
    }


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


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    candidates = _build_url_candidates(req.url)
    if not candidates:
        raise HTTPException(status_code=400, detail="Invalid URL input")

    fetched = await _fetch_first_working(candidates)
    host = _hostname_from_url(fetched.final_url)
    ip = _resolve_ip(host)

    # SSL ok: daca final_url e https si fetch a reusit cu TLS verify (httpx default)
    ssl_ok = urlparse(fetched.final_url).scheme == "https"

    html_analysis = _analyze_html(fetched.final_url, fetched.html)
    links_sample = html_analysis["links"]["extracted_sample"]

    # checks async in paralel
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

    # sitemap from robots (optional)
    sitemap_from_robots: List[str] = []
    if robots_ok and robots_text:
        for line in robots_text.splitlines():
            if line.lower().startswith("sitemap:"):
                v = line.split(":", 1)[1].strip()
                if v:
                    sitemap_from_robots.append(v)

    tech = _detect_tech(fetched.html)

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
    }

    checks = {
        "fetch": {
            "fetched_url": fetched.fetched_url,
            "final_url": fetched.final_url,
            "status_code": fetched.status_code,
            "redirect_chain": fetched.redirect_chain,
        }
    }

    return AnalyzeResponse(
        input_url=req.url,
        normalized_candidates=candidates,
        fetched_url=fetched.fetched_url,
        final_url=fetched.final_url,
        redirect_chain=fetched.redirect_chain,
        status_code=fetched.status_code,
        ip_address=ip,
        ssl_ok=ssl_ok,
        seo=seo,
        structured_data=structured_data,
        social=social,
        tech=tech,
        checks=checks,
    )
