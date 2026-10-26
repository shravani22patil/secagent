def test_dashboard_served_with_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "SecAgent" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_static_assets_and_existing_routes_still_work(client):
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/health").json()["tool_mode"] == "mock"
    assert client.get("/docs").status_code == 200


def test_frontend_never_uses_innerhtml():
    from app.main import WEB_DIR
    js = (WEB_DIR / "static" / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "eval(" not in js


def _parse_nav():
    """Collect nav tabs, goto-buttons and view sections from the real index.html (stdlib only)."""
    from html.parser import HTMLParser

    from app.main import WEB_DIR

    class P(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tabs, self.gotos, self.views = [], [], set()

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "button" and "tab" in (a.get("class") or "").split():
                self.tabs.append(a)
            if "data-goto" in a:
                self.gotos.append(a["data-goto"])
            if tag == "section" and "view" in (a.get("class") or "").split():
                self.views.add(a.get("id"))

    p = P()
    p.feed((WEB_DIR / "index.html").read_text(encoding="utf-8"))
    return p


def test_nav_tabs_are_never_disabled_and_map_to_real_sections():
    # Regression: the Report tab used to ship with `disabled`; browsers fire no click events on
    # disabled buttons, so clicking it did nothing (no console error, no network request).
    p = _parse_nav()
    assert {t["data-view"] for t in p.tabs} == {"overview", "assess", "report"}
    for t in p.tabs:
        assert "disabled" not in t, f"nav tab {t['data-view']!r} must stay clickable"
        assert f"view-{t['data-view']}" in p.views, f"no section for tab {t['data-view']!r}"
    assert all(f"view-{g}" in p.views for g in p.gotos)


def test_report_section_has_empty_state_before_any_scan():
    from app.main import WEB_DIR
    js = (WEB_DIR / "static" / "app.js").read_text(encoding="utf-8")
    assert "renderReportEmpty();" in js and "No report yet" in js
