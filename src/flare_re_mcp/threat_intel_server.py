"""Public Threat Intelligence & OSINT Reputation MCP Server (`threat-intel-mcp`).
Strictly enforces OPSEC: NEVER uploads binary samples; queries ONLY cryptographic hashes
(SHA-256, MD5, SHA-1, Imphash) and extracted network IOCs (URLs, domains, IPs).

Zero-Config by default:
  - Abuse.ch MalwareBazaar (`https://mb-api.abuse.ch/api/v1/`)
  - Abuse.ch ThreatFox (`https://threatfox-api.abuse.ch/api/v1/`)
  - Abuse.ch URLhaus (`https://urlhaus-api.abuse.ch/v1/`)
Optional API Key Enrichment:
  - VirusTotal v3 (`VT_API_KEY` environment variable)
  - Abuse.ch Auth-Key (`ABUSECH_API_KEY` environment variable)
"""

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from mcp.server import MCPServer
import pefile

from flare_re_mcp.common import (
    get_file_hashes,
    load_tool_snapshot,
    resolve_binary_path,
    save_tool_snapshot,
    update_evidence_ledger,
)

SERVER_TAG = "threat-intel-mcp"
server = MCPServer("threat-intel-osint")


def _http_json_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    form_data: Optional[Dict[str, str]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    timeout: int = 12,
) -> Dict[str, Any]:
    req_headers = {"User-Agent": "Mozilla/5.0 (flare-re-mcp ThreatIntel OSINT Client)"}
    if headers:
        req_headers.update(headers)

    body: Optional[bytes] = None
    if form_data is not None:
        body = urllib.parse.urlencode(form_data).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    try:
        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except Exception as exc:
        return {"query_status": "http_error", "error": str(exc)}


def _query_malwarebazaar(sha256: str) -> Dict[str, Any]:
    headers = {}
    auth_key = os.environ.get("ABUSECH_API_KEY") or os.environ.get("MALWAREBAZAAR_API_KEY")
    if auth_key:
        headers["Auth-Key"] = auth_key

    res = _http_json_request(
        "https://mb-api.abuse.ch/api/v1/",
        method="POST",
        headers=headers,
        form_data={"query": "get_info", "hash": sha256},
    )
    qstatus = res.get("query_status")
    if qstatus == "ok" and res.get("data"):
        entry = res["data"][0]
        return {
            "found": True,
            "signature_family": entry.get("signature"),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_seen"),
            "file_name": entry.get("file_name"),
            "file_type": entry.get("file_type"),
            "tags": entry.get("tags", []),
            "delivery_method": entry.get("delivery_method"),
            "intelligence": entry.get("intelligence", {}),
            "vendor_intel": list((entry.get("vendor_intel") or {}).keys()),
        }
    return {"found": False, "query_status": qstatus or "hash_not_found"}


def _query_threatfox_hash(sha256: str) -> Dict[str, Any]:
    headers = {}
    auth_key = os.environ.get("ABUSECH_API_KEY")
    if auth_key:
        headers["Auth-Key"] = auth_key

    res = _http_json_request(
        "https://threatfox-api.abuse.ch/api/v1/",
        method="POST",
        headers=headers,
        json_data={"query": "search_hash", "hash": sha256},
    )
    qstatus = res.get("query_status")
    if qstatus == "ok" and res.get("data"):
        return {
            "found": True,
            "matches": res["data"][:10],
        }
    return {"found": False, "query_status": qstatus or "no_result"}


def _query_urlhaus_payload(sha256: str) -> Dict[str, Any]:
    headers = {}
    auth_key = os.environ.get("ABUSECH_API_KEY")
    if auth_key:
        headers["Auth-Key"] = auth_key

    res = _http_json_request(
        "https://urlhaus-api.abuse.ch/v1/payload/",
        method="POST",
        headers=headers,
        form_data={"sha256_hash": sha256},
    )
    qstatus = res.get("query_status")
    if qstatus == "ok":
        return {
            "found": True,
            "signature": res.get("signature"),
            "firstseen": res.get("firstseen"),
            "lastseen": res.get("lastseen"),
            "url_count": res.get("url_count"),
            "urls": [u.get("url") for u in (res.get("urls") or [])[:10]],
        }
    return {"found": False, "query_status": qstatus or "no_results"}


def _query_virustotal(sha256: str) -> Dict[str, Any]:
    vt_key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return {
            "configured": False,
            "found": False,
            "message": "VT_API_KEY not set in environment; using public OSINT repositories and web search queries.",
        }

    res = _http_json_request(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        method="GET",
        headers={"x-apikey": vt_key},
    )
    if "data" in res and isinstance(res["data"], dict):
        attrs = res["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        pop_threat = attrs.get("popular_threat_classification", {})
        return {
            "configured": True,
            "found": True,
            "malicious_detections": stats.get("malicious", 0),
            "suspicious_detections": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if isinstance(stats, dict) else 0,
            "reputation_score": attrs.get("reputation"),
            "suggested_threat_label": pop_threat.get("suggested_threat_label"),
            "meaningful_name": attrs.get("meaningful_name"),
            "tags": attrs.get("tags", []),
            "First_submission_date": attrs.get("first_submission_date"),
        }
    return {"configured": True, "found": False, "raw_status": res.get("error") or res.get("query_status")}


@server.tool(
    name="ti_lookup_binary_reputation",
    description=(
        "[OPSEC-Safe Threat Intelligence Lookup] Query public malware repositories (MalwareBazaar, ThreatFox, URLhaus, "
        "and VirusTotal v3 if `VT_API_KEY` is configured) strictly by cryptographic hash (SHA-256, MD5, SHA-1, Imphash) "
        "without ever uploading the binary. Also generates ready-to-run OSINT web search queries for `threat-intel-osint-worker`."
    ),
)
def ti_lookup_binary_reputation(file_path: str, force_refresh: bool = False) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        if not force_refresh:
            cached = load_tool_snapshot(safe_path, "threat_intel")
            if cached:
                return json.dumps(cached, ensure_ascii=False, indent=2)

        hashes = get_file_hashes(safe_path)
        sha256 = hashes["sha256"]
        md5 = hashes["md5"]
        imphash = None
        try:
            pe = pefile.PE(safe_path, fast_load=False)
            imphash = pe.get_imphash()
            pe.close()
        except Exception:
            pass

        mb_res = _query_malwarebazaar(sha256)
        tf_res = _query_threatfox_hash(sha256)
        uh_res = _query_urlhaus_payload(sha256)
        vt_res = _query_virustotal(sha256)

        # Check cached FLOSS/DIE for PDB path or notable domains to build high-precision OSINT web queries
        floss_snap = load_tool_snapshot(safe_path, "floss") or {}
        iocs = floss_snap.get("ioc_and_api_enrichment", {}).get("iocs_by_category", {})
        pdb_paths = iocs.get("pdb_path", [])
        urls = iocs.get("url", [])

        recommended_web_queries = [
            f'"{sha256}" OR "{md5}" malware analysis',
        ]
        if imphash:
            recommended_web_queries.append(f'imphash "{imphash}" malware')
        for pdb in pdb_paths[:2]:
            pdb_name = os.path.basename(pdb.replace("\\", "/"))
            recommended_web_queries.append(f'"{pdb_name}" OR "{pdb}" malware')
        for u in urls[:2]:
            recommended_web_queries.append(f'"{u}" malware')

        any_public_hit = bool(mb_res.get("found") or tf_res.get("found") or uh_res.get("found") or vt_res.get("found"))
        reputation_verdict = (
            "KNOWN_PUBLIC_MALWARE"
            if any_public_hit
            else "UNLISTED_HASH_CHECK_OSINT_AND_BEHAVIOR"
        )

        payload = {
            "status": "success",
            "tool": "Threat Intelligence & OSINT (MalwareBazaar + ThreatFox + URLhaus + VirusTotal)",
            "opsec_policy": "HASH_ONLY_NO_FILE_UPLOAD",
            "file_path": safe_path,
            "hashes": {**hashes, "imphash": imphash},
            "reputation_verdict": reputation_verdict,
            "repositories": {
                "malwarebazaar_abuse_ch": mb_res,
                "threatfox_abuse_ch": tf_res,
                "urlhaus_abuse_ch": uh_res,
                "virustotal_v3": vt_res,
            },
            "osint_portal_links": {
                "virustotal": f"https://www.virustotal.com/gui/file/{sha256}",
                "malwarebazaar": f"https://bazaar.abuse.ch/sample/{sha256}/",
                "threatfox": f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{sha256}",
                "hybrid_analysis": f"https://www.hybrid-analysis.com/sample/{sha256}",
                "triage": f"https://tria.ge/s?q={sha256}",
            },
            "recommended_web_search_queries": recommended_web_queries,
        }
        save_tool_snapshot(safe_path, "threat_intel", payload)
        update_evidence_ledger(
            safe_path,
            source_tool="threat-intel-mcp",
            observations=[
                {
                    "type": "threat_intel_reputation",
                    "sha256": sha256,
                    "reputation_verdict": reputation_verdict,
                    "malwarebazaar_found": mb_res.get("found", False),
                    "virustotal_found": vt_res.get("found", False),
                }
            ],
        )
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="ti_lookup_iocs",
    description=(
        "Cross-check extracted network IOCs (URLs, domains, IPv4 addresses) from a binary against "
        "Abuse.ch ThreatFox and URLhaus threat intelligence feeds."
    ),
)
def ti_lookup_iocs(file_path: str) -> str:
    try:
        candidate = os.path.abspath(os.path.expanduser(file_path.strip().strip('"').strip("'")))
        if os.path.isfile(candidate):
            safe_path = resolve_binary_path(file_path)
            floss_snap = load_tool_snapshot(safe_path, "floss") or {}
            iocs = floss_snap.get("ioc_and_api_enrichment", {}).get("iocs_by_category", {})
            indicators = (iocs.get("url", [])[:10] + iocs.get("ipv4", [])[:10])
        else:
            safe_path = None
            indicators = [x.strip() for x in file_path.split(",") if x.strip()][:20]

        ioc_results = []
        for indicator in indicators:
            res = _http_json_request(
                "https://threatfox-api.abuse.ch/api/v1/",
                method="POST",
                json_data={"query": "search_ioc", "search_term": indicator},
            )
            ioc_results.append({
                "indicator": indicator,
                "threatfox_found": res.get("query_status") == "ok",
                "matches": (res.get("data") or [])[:3] if res.get("query_status") == "ok" else [],
            })

        return json.dumps({
            "status": "success",
            "file_path": safe_path,
            "checked_indicators_count": len(ioc_results),
            "ioc_reputation_results": ioc_results,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
