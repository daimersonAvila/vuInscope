"""Inbound HTTP adapter (Flask): translates HTTP <-> use cases and applies all web-security controls."""
from __future__ import annotations

import logging
import threading
from functools import wraps

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from ....application.use_cases import ScanService
from ....bootstrap import Container, build_container
from ....config import Settings
from ....domain.errors import (AIUnavailableError, ArchiveError, AuthError, DuplicateVulnerabilityError,
                               NotFoundError, RateLimitedError, ValidationError)
from ....domain.i18n_es import RULE_TEXT_ES, norm_lang
from ....domain.rules import FILE_RULES, RULES, find_rule_meta
from .ratelimit import RateLimiter

log = logging.getLogger("vulnscope")
MAX_JSON_BYTES = 256 * 1024


def create_app(settings: Settings | None = None, container: Container | None = None) -> Flask:
    settings = settings or Settings.from_env()
    c = container or build_container(settings)
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(SECRET_KEY=settings.secret_key, MAX_CONTENT_LENGTH=(settings.max_upload_mb + 1) * 1024 * 1024,
                      JSON_SORT_KEYS=False, SEND_FILE_MAX_AGE_DEFAULT=3600)
    if settings.trusted_proxies:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=settings.trusted_proxies, x_proto=settings.trusted_proxies,
                                x_host=settings.trusted_proxies)
    limiter = RateLimiter()
    scan_slots = threading.BoundedSemaphore(3)
    scale = settings.rate_scale

    # ------------------------------------------------------------ helpers
    def err(message, status, **extra):
        return jsonify({"error": message, **extra}), status

    def limit(bucket, n, window):
        def deco(fn):
            @wraps(fn)
            def inner(*a, **kw):
                ok, retry = limiter.check(bucket, request.remote_addr or "?", max(1, int(n * scale)), window)
                if not ok:
                    resp = jsonify({"error": "Too many requests. Slow down and retry shortly."})
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry)
                    return resp
                return fn(*a, **kw)
            return inner
        return deco

    def auth_required(fn):
        @wraps(fn)
        def inner(*a, **kw):
            parts = request.headers.get("Authorization", "").split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return err("Use 'Authorization: Bearer <token>'", 401)
            try:
                g.user = c.auth.verify(parts[1])
            except AuthError as e:
                return err(str(e), 401)
            return fn(*a, **kw)
        return inner

    def body():
        return request.get_json(silent=True)

    # ------------------------------------------------------- request hooks
    @app.before_request
    def guard():
        if settings.allowed_hosts and request.host.split(":")[0].lower() not in settings.allowed_hosts:
            return err("Invalid host", 400)
        if request.endpoint != "scan" and (request.content_length or 0) > MAX_JSON_BYTES:
            return err("Request body too large", 413)
        if settings.https_only and not request.is_secure and request.endpoint != "healthz":
            return err("HTTPS required", 400)

    @app.after_request
    def secure_headers(resp):
        csp = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
               "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
        if settings.https_only:
            csp += "; upgrade-insecure-requests"
            resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        h = resp.headers
        h["Content-Security-Policy"] = csp
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Server"] = "vulnscope"
        if request.path.startswith(("/api", "/login")) or request.path == "/healthz":
            h["Cache-Control"] = "no-store"
        return resp

    # --------------------------------------------------- error translation
    @app.errorhandler(ValidationError)
    def _v(e): return err(str(e), 400)

    @app.errorhandler(NotFoundError)
    def _nf(e): return err(str(e), 404)

    @app.errorhandler(ArchiveError)
    def _ar(e): return err(str(e), 422)

    @app.errorhandler(RateLimitedError)
    def _rl(e): return err(str(e), 429)

    @app.errorhandler(DuplicateVulnerabilityError)
    def _dup(e):
        return err("An identical vulnerability is already registered, so it was not created.", 409,
                   code="duplicate_vulnerability", existing_id=e.existing_id)

    @app.errorhandler(404)
    def _404(_): return err("Not found", 404)

    @app.errorhandler(405)
    def _405(_): return err("Method not allowed", 405)

    @app.errorhandler(413)
    def _413(_): return err(f"File too large. Maximum upload is {settings.max_upload_mb} MB.", 413)

    @app.errorhandler(Exception)
    def _500(e):
        if isinstance(e, HTTPException):
            return err(e.description or e.name, e.code or 500)
        log.exception("unhandled error")  # details only in server logs, never in the response
        return err("Internal server error", 500)

    # ------------------------------------------------------------- pages
    @app.get("/")
    def landing(): return render_template("landing.html", rule_count=len(RULES) + len(FILE_RULES) + 1)

    @app.get("/app")
    def console(): return render_template("app.html")

    @app.get("/healthz")
    def healthz(): return jsonify({"status": "ok"})

    @app.get("/api")
    def api_info():
        return jsonify({"name": "VulnScope API", "version": "1.0", "resource": "/api/vulnerabilidades"})

    # -------------------------------------------------------------- auth
    @app.post("/login")
    @limit("login", 8, 60)
    def login():
        data = body()
        if not isinstance(data, dict) or not isinstance(data.get("username"), str) or not isinstance(data.get("clave"), str):
            return err("username and clave are required", 400)
        try:
            return jsonify(c.auth.login(data["username"][:100], data["clave"][:200]))
        except AuthError:
            return err("Invalid credentials", 401)

    # ---------------------------------------------------------- registry
    @app.get("/api/vulnerabilidades")
    @limit("read", 120, 60)
    def list_v(): return jsonify([v.to_dict() for v in c.registry.list()])

    @app.get("/api/vulnerabilidades/<int:vid>")
    @limit("read", 120, 60)
    def get_v(vid): return jsonify(c.registry.get(vid).to_dict())

    @app.post("/api/vulnerabilidades")
    @auth_required
    @limit("write", 60, 60)
    def create_v():
        v = c.registry.create(body())
        return jsonify({"id": v.id, "message": "Vulnerability registered"}), 201

    @app.post("/api/vulnerabilidades/bulk")
    @auth_required
    @limit("write", 10, 60)
    def bulk_v():
        data = body()
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            return err("Send {\"findings\": [...]}", 400)
        return jsonify(c.registry.register_findings(data["findings"]))

    @app.put("/api/vulnerabilidades/<int:vid>")
    @auth_required
    @limit("write", 60, 60)
    def update_v(vid):
        c.registry.update(vid, body())
        return jsonify({"message": "Vulnerability updated"})

    @app.delete("/api/vulnerabilidades/<int:vid>")
    @auth_required
    @limit("write", 60, 60)
    def delete_v(vid):
        c.registry.delete(vid)
        return jsonify({"message": "Vulnerability deleted"})

    @app.get("/api/vulnerabilidades/<int:vid>/playbook")
    @auth_required
    @limit("read", 120, 60)
    def registry_playbook(vid): return jsonify(c.registry.playbook(vid, norm_lang(request.args.get("lang"))))

    # -------------------------------------------------------------- scan
    @app.post("/api/scan")
    @limit("scan", 6, 60)
    def scan():
        f = request.files.get("archive")
        if f is None or not f.filename:
            return err("Attach a project archive in the 'archive' field.", 400)
        data = f.read(settings.max_upload_mb * 1024 * 1024 + 1)
        if len(data) > settings.max_upload_mb * 1024 * 1024:
            return err(f"File too large. Maximum upload is {settings.max_upload_mb} MB.", 413)
        if not scan_slots.acquire(blocking=False):
            return err("The scanner is busy. Try again in a few seconds.", 503)
        try:
            result = c.scans.run(data)
        finally:
            scan_slots.release()
        return jsonify(result)

    @app.get("/api/rules")
    @limit("read", 120, 60)
    def rules():
        return jsonify([{"id": r.id, "title": r.title, "cwe": r.cwe, "severity": r.severity, "category": r.category}
                        for r in RULES])

    @app.get("/api/rule-text")
    @limit("read", 120, 60)
    def rule_text():
        """Localised title + fix for every rule id (the client overlays them on scan results)."""
        es = norm_lang(request.args.get("lang")) == "es"
        ids = [r.id for r in RULES] + [r[0] for r in FILE_RULES] + ["FIL004"]
        out = {}
        for rid in ids:
            title, _cwe, _sev, _cat, fix, _ex = find_rule_meta(rid)
            out[rid] = {"title": RULE_TEXT_ES[rid][0], "fix": RULE_TEXT_ES[rid][1]} if es else {"title": title, "fix": fix}
        return jsonify(out)

    @app.post("/api/playbook")
    @limit("read", 60, 60)
    def rule_playbook():
        data = body()
        if not isinstance(data, dict) or not isinstance(data.get("rule_id"), str):
            return err("rule_id is required", 400)
        return jsonify(ScanService.playbook_for_rule(data["rule_id"], norm_lang(data.get("lang"))))

    # ---------------------------------------------------------------- AI
    @app.post("/api/ai/explain")
    @limit("ai", 12, 60)
    def ai_explain():
        data = body()
        if not isinstance(data, dict) or not isinstance(data.get("finding"), dict):
            return err("Send {\"finding\": {...}}", 400)
        return jsonify(c.advisor.explain_finding(data["finding"], norm_lang(data.get("lang"))))

    @app.post("/api/ai/summary")
    @limit("ai", 12, 60)
    def ai_summary():
        data = body()
        if not isinstance(data, dict):
            return err("Send a JSON object", 400)
        return jsonify(c.advisor.summarize_scan(data, norm_lang(data.get("lang"))))

    # ----------------------------------------------------------- Markov
    @app.get("/api/markov/lifecycle")
    @limit("read", 60, 60)
    def lifecycle():
        return jsonify(c.lifecycle.forecast(request.args.get("from", "abierta")))

    return app
