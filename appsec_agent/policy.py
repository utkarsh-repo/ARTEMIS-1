from __future__ import annotations
import ipaddress, json, socket
from pathlib import Path
from urllib.parse import urlparse, unquote
import posixpath

STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

class PolicyError(ValueError):
    pass

def load_policy(path):
    p = json.loads(Path(path).read_text(encoding="utf-8"))
    required = ("base_url", "allowed_hosts", "allowed_path_prefixes", "allowed_methods", "max_requests")
    missing = [k for k in required if k not in p]
    if missing:
        raise PolicyError("Missing policy fields: " + ", ".join(missing))
    if not isinstance(p["base_url"], str) or not p["base_url"].strip():
        raise PolicyError("base_url must be a non-empty absolute URL")
    base = urlparse(p["base_url"])
    if not base.hostname or base.username or base.password or base.fragment:
        raise PolicyError("base_url must be an absolute URL without credentials or fragments")
    try:
        base_port = base.port
    except ValueError as exc:
        raise PolicyError("base_url contains an invalid port") from exc
    if base_port is not None and not (1 <= base_port <= 65535):
        raise PolicyError("base_url port must be between 1 and 65535")
    if p.get("https_only", True) and base.scheme != "https":
        raise PolicyError("https_only is enabled but base_url is not HTTPS")
    hosts = p["allowed_hosts"]
    if not isinstance(hosts, list) or not hosts or any(
        not isinstance(h, str) or not h or h != h.lower() or "*" in h or h.endswith(".")
        or any(ch.isspace() for ch in h) for h in hosts
    ):
        raise PolicyError("allowed_hosts must be exact lowercase hostnames without wildcards, whitespace, or trailing dots")
    if len(set(hosts)) != len(hosts):
        raise PolicyError("allowed_hosts must not contain duplicates")
    if base.hostname.lower() not in hosts:
        raise PolicyError("base_url hostname must be in allowed_hosts")
    default_port = base_port or (443 if base.scheme == "https" else 80)
    allowed_ports = p.get("allowed_ports", [default_port])
    if (not isinstance(allowed_ports, list) or not allowed_ports
            or any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in allowed_ports)
            or len(set(allowed_ports)) != len(allowed_ports)):
        raise PolicyError("allowed_ports must be a non-empty list of unique ports between 1 and 65535")
    p["allowed_ports"] = sorted(allowed_ports)
    if default_port not in p["allowed_ports"]:
        raise PolicyError("base_url port must be included in allowed_ports")
    if not isinstance(p["allowed_methods"], list) or not p["allowed_methods"] or any(not isinstance(m, str) for m in p["allowed_methods"]):
        raise PolicyError("allowed_methods must be a non-empty list of HTTP method strings")
    if not set(m.upper() for m in p["allowed_methods"]).issubset({"GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"}):
        raise PolicyError("Unsupported method in allowed_methods")
    if not isinstance(p["max_requests"], int) or p["max_requests"] < 1:
        raise PolicyError("max_requests must be a positive integer")
    p["allowed_methods"] = [m.upper() for m in p["allowed_methods"]]
    if not isinstance(p["allowed_path_prefixes"], list) or not p["allowed_path_prefixes"]:
        raise PolicyError("allowed_path_prefixes must be a non-empty list")
    for prefix in p["allowed_path_prefixes"]:
        if not isinstance(prefix,str) or not prefix.startswith("/") or "?" in prefix or "#" in prefix or "\\" in prefix or "\x00" in prefix:
            raise PolicyError("allowed_path_prefixes must be absolute, unambiguous paths without query/fragment")
    return p


def resolve_target_ips(policy, url):
    """Resolve once and validate every candidate IP before a pinned connection."""
    u = urlparse(url)
    if not u.hostname:
        raise PolicyError("URL has no hostname")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
        infos = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
    except (OSError, ValueError) as exc:
        raise PolicyError(f"DNS resolution failed: {exc}") from exc
    ips = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError, TypeError) as exc:
            raise PolicyError("DNS returned an invalid IP address") from exc
        if not policy.get("allow_private_networks", False) and not ip.is_global:
            raise PolicyError(f"Private/reserved IP blocked: {ip}")
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise PolicyError("DNS returned no usable addresses")
    return ips

def validate_url(policy, url, method, resolve_dns=True):
    method = method.upper()
    if not isinstance(url, str) or any(ord(ch) < 0x20 or ch == "\\" for ch in url):
        raise PolicyError("URL contains control characters or ambiguous backslashes")
    try:
        u = urlparse(url)
    except ValueError as exc:
        raise PolicyError("Malformed URL") from exc
    if u.scheme not in ("https", "http") or not u.hostname:
        raise PolicyError("Only absolute HTTP(S) URLs are accepted")
    if u.fragment:
        raise PolicyError("URL fragments are not accepted for test requests")
    try:
        port = u.port
    except ValueError as exc:
        raise PolicyError("URL contains an invalid port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise PolicyError("URL port must be between 1 and 65535")
    effective_port = port or (443 if u.scheme == "https" else 80)
    allowed_ports = policy.get("allowed_ports")
    if allowed_ports is None:
        base = urlparse(policy.get("base_url", ""))
        try:
            base_port = base.port
        except ValueError as exc:
            raise PolicyError("policy base_url contains an invalid port") from exc
        allowed_ports = [base_port or (443 if base.scheme == "https" else 80)]
    if (not isinstance(allowed_ports, (list, tuple, set)) or not allowed_ports
            or any(not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= 65535 for item in allowed_ports)
            or len(set(allowed_ports)) != len(allowed_ports)):
        raise PolicyError("allowed_ports must contain unique integer ports between 1 and 65535")
    if effective_port not in allowed_ports:
        raise PolicyError(f"Port {effective_port} is not in allowed_ports")
    if policy.get("https_only", True) and u.scheme != "https":
        raise PolicyError("Non-HTTPS URL blocked")
    if u.username or u.password:
        raise PolicyError("URL-embedded credentials are forbidden")
    if u.hostname.lower() not in policy["allowed_hosts"]:
        raise PolicyError(f"Host {u.hostname.lower()!r} is not allowlisted")
    if method not in policy["allowed_methods"]:
        raise PolicyError(f"Method {method} is not in allowed_methods")
    raw_path = u.path or "/"
    # Normalize repeatedly so double-encoded traversal/separators cannot pass
    # this gate and be decoded later by a proxy or application server.
    decoded_path = raw_path
    for _ in range(5):
        next_path = unquote(decoded_path)
        if next_path == decoded_path:
            break
        decoded_path = next_path
    else:
        raise PolicyError("Path has excessive nested URL encoding")
    if __import__("re").search(r"%[0-9a-fA-F]{2}", decoded_path):
        raise PolicyError("Ambiguous residual URL encoding blocked")
    if "\x00" in decoded_path or "\\" in decoded_path:
        raise PolicyError("Ambiguous path blocked")
    if any(segment == ".." for segment in decoded_path.split("/")):
        raise PolicyError("Path traversal sequence blocked")
    normalized = posixpath.normpath("/" + decoded_path.lstrip("/"))
    def prefix_matches(prefix):
        # Treat path prefixes as path boundaries: /api must not authorize /apix.
        clean = posixpath.normpath("/" + prefix.lstrip("/"))
        if clean == "/":
            return True
        return normalized == clean or normalized.startswith(clean.rstrip("/") + "/")
    if not any(prefix_matches(prefix) for prefix in policy["allowed_path_prefixes"]):
        raise PolicyError(f"Path {normalized!r} is outside allowed_path_prefixes")
    if method in STATE_CHANGING:
        if not policy.get("allow_state_changing_tests", False):
            raise PolicyError("State-changing methods are disabled by policy")
        if os_ack() != "I_ACKNOWLEDGE_DISPOSABLE_LAB_DATA":
            raise PolicyError("Run-level acknowledgement for state-changing lab tests is missing")
    if resolve_dns:
        resolve_target_ips(policy, url)
    return url

def os_ack():
    import os
    return os.environ.get("APPSEC_LAB_ACK_STATE_CHANGES", "")
