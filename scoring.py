def calculate_general_score(data: dict) -> dict:
    score = 100
    missing = 0
    improvements = 0
    errors = 0

    seo = data.get("seo", {})
    tech = data.get("tech", {})
    checks = data.get("checks", {})

    # ---------------- SEO ----------------
    title = seo.get("title", {}).get("value")
    meta_desc = seo.get("meta_description", {}).get("value")
    images = seo.get("images", {})

    if not title:
        score -= 10
        missing += 10

    if not meta_desc:
        score -= 10
        missing += 10

    if images:
        if images.get("missing_alt", 0) > 0:
            score -= 5
            improvements += 5

    # ---------------- TECH ----------------
    if not tech.get("google_analytics"):
        score -= 5
        missing += 5

    if not tech.get("google_tag_manager"):
        score -= 5
        missing += 5

    if not tech.get("google_maps"):
        improvements += 2

    # ---------------- SSL ----------------
    ssl = checks.get("ssl_certificate", {})
    if not ssl or not ssl.get("present"):
        score -= 20
        errors += 20

    # ---------------- WORDPRESS ----------------
    wp = tech.get("wordpress", {})
    if wp and wp.get("is_wordpress"):
        if not wp.get("version"):
            improvements += 5

    # ---------------- LINKS ----------------
    broken = seo.get("links", {}).get("broken_links", {})
    if broken:
        broken_count = broken.get("broken", 0)
        if broken_count > 0:
            score -= min(15, broken_count * 2)
            errors += min(15, broken_count * 2)

    # ---------------- NORMALIZARE ----------------
    score = max(0, min(100, score))

    implemented = score
    to_improve = improvements
    missing_pct = 100 - score

    return {
        "general_score": score,
        "implemented_percent": implemented,
        "improvement_percent": min(100, to_improve),
        "missing_or_errors_percent": min(100, missing_pct + errors),
    }