"""Cloudflare client/v4 simulator.

Serves the phase-01 Cloudflare fixtures verbatim behind /client/v4 paths.
Bearer token is compared against env CLOUDFLARE_SIM_TOKEN (default
`demo-token`). Error codes (6003, 9109) approximate Cloudflare's real codes.
"""
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .fixtures import INDEX, DOMAINS

app = FastAPI(title="cloudflare-simulator")
TOKEN = os.environ.get("CLOUDFLARE_SIM_TOKEN", "demo-token")


def envelope(result, **extra):
    out = {"success": True, "errors": [], "messages": [], "result": result}
    out.update(extra)
    return out


def cf_error(status, code, message):
    return JSONResponse(status_code=status, content={
        "success": False,
        "errors": [{"code": code, "message": message}],
        "messages": [], "result": None})


def result_info(page, per_page, count, total):
    return {"page": page, "per_page": per_page, "count": count,
            "total_count": total, "total_pages": max(1, -(-total // per_page))}


@app.middleware("http")
async def bearer_auth(request: Request, call_next):
    if request.url.path == "/healthz":
        return await call_next(request)
    auth = request.headers.get("authorization", "")
    if not auth or not auth.startswith("Bearer "):
        return cf_error(400, 6003, "Invalid request headers: missing or malformed Authorization")
    if auth[len("Bearer "):] != TOKEN:
        return cf_error(403, 9109, "Invalid access token")
    return await call_next(request)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "provider": "cloudflare", "domains": DOMAINS}


@app.get("/client/v4/zones")
def list_zones(name: str = None, page: int = 1, per_page: int = 20):
    zones = [INDEX.cf[d]["zone"]["result"] for d in DOMAINS]
    if name:
        zones = [z for z in zones if z["name"] == name]
    return envelope(zones, result_info=result_info(page, per_page, len(zones), len(zones)))


def _zone_or_404(zone_id):
    domain = INDEX.zone_by_id.get(zone_id)
    if domain is None:
        return None, cf_error(404, 1001, "Zone not found")
    return domain, None


@app.get("/client/v4/zones/{zone_id}")
def get_zone(zone_id: str):
    domain, err = _zone_or_404(zone_id)
    if err:
        return err
    return envelope(INDEX.cf[domain]["zone"]["result"])


@app.get("/client/v4/zones/{zone_id}/settings")
def get_settings(zone_id: str):
    domain, err = _zone_or_404(zone_id)
    if err:
        return err
    return INDEX.cf[domain]["settings"]


@app.get("/client/v4/zones/{zone_id}/settings/{setting_id}")
def get_setting(zone_id: str, setting_id: str):
    domain, err = _zone_or_404(zone_id)
    if err:
        return err
    for s in INDEX.cf[domain]["settings"]["result"]:
        if s["id"] == setting_id:
            return envelope(s)
    return cf_error(404, 1002, f"Setting '{setting_id}' not found")


@app.get("/client/v4/zones/{zone_id}/rulesets")
def list_rulesets(zone_id: str):
    domain, err = _zone_or_404(zone_id)
    if err:
        return err
    rulesets = [{k: v for k, v in rs.items() if k != "rules"}
                for rs in INDEX.cf[domain]["rulesets"]["result"]]
    return envelope(rulesets,
                    result_info=result_info(1, 50, len(rulesets), len(rulesets)))


@app.get("/client/v4/zones/{zone_id}/rulesets/phases/{phase}/entrypoint")
def get_entrypoint(zone_id: str, phase: str):
    domain, err = _zone_or_404(zone_id)
    if err:
        return err
    for rs in INDEX.cf[domain]["rulesets"]["result"]:
        if rs["phase"] == phase:
            return envelope(rs)
    return cf_error(404, 1003, f"No ruleset for phase '{phase}'")


@app.get("/client/v4/zones/{zone_id}/rulesets/{ruleset_id}")
def get_ruleset(zone_id: str, ruleset_id: str):
    domain, err = _zone_or_404(zone_id)
    if err:
        return err
    for rs in INDEX.cf[domain]["rulesets"]["result"]:
        if rs["id"] == ruleset_id:
            return envelope(rs)
    return cf_error(404, 1004, "Ruleset not found")


@app.get("/client/v4/zones/{zone_id}/dns_records")
def get_dns_records(zone_id: str, page: int = 1, per_page: int = 20):
    domain, err = _zone_or_404(zone_id)
    if err:
        return err
    records = INDEX.cf[domain]["dns_records"]["result"]
    total = len(records)
    start = (page - 1) * per_page
    items = records[start:start + per_page]
    return envelope(items, result_info=result_info(page, per_page, len(items), total))
