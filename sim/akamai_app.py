"""Akamai PAPI + App Sec simulator.

Serves the phase-01 Akamai fixtures verbatim behind PAPI v1 and App Sec v1
paths. `Authorization` must be a well-formed EdgeGrid header
(`EG1-HMAC-SHA256 client_token=...;access_token=...;timestamp=...;nonce=...;
signature=...`) but the signature itself is NOT verified — this is a demo
simulator, not an auth implementation.
"""
import copy
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .fixtures import INDEX, DOMAINS

app = FastAPI(title="akamai-simulator")

ID_PREFIXES = ("prp_", "ctr_", "grp_", "act_", "aid_", "ehn_", "cpc_")
AUTH_RE = re.compile(r"^EG1-HMAC-SHA256\s+\S+;\S+;\S+;\S+;signature=\S+$")


def problem(status, title, detail="", instance=""):
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        content={"type": f"https://sim.rbcdemo.ca/problems/{title.lower().replace(' ', '-')}",
                 "title": title, "detail": detail, "status": status,
                 "instance": instance})


@app.middleware("http")
async def edgegrid_auth(request: Request, call_next):
    if request.url.path == "/healthz":
        return await call_next(request)
    auth = request.headers.get("authorization", "")
    if not auth or not AUTH_RE.match(auth):
        return problem(401, "Unauthorized",
                       "missing or malformed EdgeGrid authorization header",
                       request.url.path)
    return await call_next(request)


def strip_prefixes(node):
    """Recursively remove ID prefixes from every string value
    (PAPI-Use-Prefixes: false semantics)."""
    if isinstance(node, dict):
        return {k: strip_prefixes(v) for k, v in node.items()}
    if isinstance(node, list):
        return [strip_prefixes(v) for v in node]
    if isinstance(node, str):
        for p in ID_PREFIXES:
            if node.startswith(p):
                return node[len(p):]
    return node


def maybe_strip(doc, request: Request):
    if request.headers.get("PAPI-Use-Prefixes", "true").lower() == "false":
        return strip_prefixes(copy.deepcopy(doc))
    return doc


@app.get("/healthz")
def healthz():
    return {"status": "ok", "provider": "akamai", "domains": DOMAINS}


@app.get("/papi/v1/properties")
def list_properties(request: Request, contractId: str = None, groupId: str = None):
    if (contractId is None) != (groupId is None):
        return problem(400, "Bad Request",
                       "contractId and groupId must be supplied together",
                       str(request.url.path))
    items = INDEX.properties["properties"]["items"]
    if contractId is not None:
        items = [i for i in items
                 if i.get("contractId") == contractId and i.get("groupId") == groupId]
    return maybe_strip({"accountId": INDEX.properties["accountId"],
                        "contractId": INDEX.properties["contractId"],
                        "properties": {"items": items}}, request)


@app.get("/papi/v1/properties/{property_id}")
def get_property(property_id: str, request: Request):
    pid = property_id if property_id.startswith("prp_") else f"prp_{property_id}"
    if pid not in INDEX.by_property:
        return problem(404, "Not Found", f"unknown property {property_id}",
                       request.url.path)
    items = [i for i in INDEX.properties["properties"]["items"] if i["propertyId"] == pid]
    return maybe_strip({"accountId": INDEX.properties["accountId"],
                        "contractId": INDEX.properties["contractId"],
                        "properties": {"items": items}}, request)


def _domain_or_404(property_id, request):
    pid = property_id if property_id.startswith("prp_") else f"prp_{property_id}"
    domain = INDEX.by_property.get(pid)
    if domain is None:
        return None, problem(404, "Not Found", f"unknown property {property_id}",
                             request.url.path)
    return domain, None


def _version_or_404(property_id, version, request):
    pid = property_id if property_id.startswith("prp_") else f"prp_{property_id}"
    meta = INDEX.property_meta[pid]
    if version != meta["latestVersion"]:
        return problem(404, "Not Found",
                       f"property version {version} does not exist (latest is "
                       f"{meta['latestVersion']})", request.url.path)
    return None


@app.get("/papi/v1/properties/{property_id}/versions/{version}/rules")
def get_rules(property_id: str, version: int, request: Request):
    domain, err = _domain_or_404(property_id, request)
    if err:
        return err
    err = _version_or_404(property_id, version, request)
    if err:
        return err
    doc = INDEX.akamai[domain]["rules"]
    if request.headers.get("if-none-match") == doc.get("etag"):
        return Response(status_code=304)
    return JSONResponse(content=maybe_strip(doc, request),
                        headers={"ETag": doc.get("etag", "")})


@app.get("/papi/v1/properties/{property_id}/versions/{version}/hostnames")
def get_hostnames(property_id: str, version: int, request: Request):
    domain, err = _domain_or_404(property_id, request)
    if err:
        return err
    err = _version_or_404(property_id, version, request)
    if err:
        return err
    doc = INDEX.akamai[domain]["hostnames"]
    if request.headers.get("if-none-match") == doc.get("etag"):
        return Response(status_code=304)
    return JSONResponse(content=maybe_strip(doc, request),
                        headers={"ETag": doc.get("etag", "")})


@app.get("/appsec/v1/configs")
def list_appsec_configs(request: Request):
    """List security configurations (real App Sec operation; shape approximates
    the live response — see docs/simulators.md)."""
    configs = []
    for (cid, _v), doc in INDEX.appsec_by_config.items():
        hostnames = sorted({h for p in doc.get("securityPolicies", [])
                            for h in p.get("hostnames", [])})
        configs.append({
            "id": cid,
            "name": doc["configName"],
            "description": f"WAF config for {', '.join(hostnames)}",
            "latestVersion": doc["configVersion"],
            "stagingVersion": doc["configVersion"],
            "productionVersion": doc["configVersion"],
            "productionHostnames": hostnames,
        })
    return maybe_strip({"configurations": configs}, request)


@app.get("/appsec/v1/export/configs/{config_id}/versions/{version}")
def get_appsec_export(config_id: int, version: int, request: Request):
    doc = INDEX.appsec_by_config.get((config_id, version))
    if doc is None:
        known = [c for c, _ in INDEX.appsec_by_config]
        return problem(404, "Not Found",
                       f"unknown config/version {config_id}/{version} "
                       f"(known configs: {known})", request.url.path)
    return maybe_strip(doc, request)
