from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pathlib import Path
from urllib.parse import urlparse
import os
import re

app = FastAPI()

SECRET_FILE = Path("/home/agent/service-account.json").resolve()
WORKSPACE = Path("/home/agent/workspace").resolve()
OUTBOX = Path("/data/agent/outbox").resolve()

ALLOWED_HOSTS = {"raw.githubusercontent.com", "api.github.com"}


def make_response(decision: str, reason: str):
    return JSONResponse(content={"decision": decision, "reason": reason})


def is_forbidden_secret_path(text: str) -> bool:
    if "/home/agent/service-account.json" in text:
        return True

    expanded = os.path.expandvars(os.path.expanduser(text))
    if "/home/agent/service-account.json" in expanded:
        return True

    if re.search(r"service-account\.json", text, re.IGNORECASE):
        return True

    return False


def normalize_path(path_str: str) -> Path:
    p = Path(os.path.expandvars(os.path.expanduser(path_str)))
    if not p.is_absolute():
        p = (WORKSPACE / p)
    return p.resolve(strict=False)


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def check_bash(command: str):
    if is_forbidden_secret_path(command):
        return "block", "Reading /home/agent/service-account.json is never permitted."

    normalized = os.path.expandvars(os.path.expanduser(command))
    if "service-account.json" in normalized:
        return "block", "Reading /home/agent/service-account.json is never permitted."

    return "allow", "Bash command does not violate the policy."


def check_write_file(path: str):
    final_path = normalize_path(path)
    if not is_inside(final_path, OUTBOX):
        return "block", "Writes are only allowed inside /data/agent/outbox/."

    return "allow", "Write stays inside the allowed outbox directory."


def check_http_request(url: str):
    parsed = urlparse(url)
    host = parsed.hostname

    if host not in ALLOWED_HOSTS:
        return "block", "Host is not in the exact allowlist."

    return "allow", "HTTP host is on the exact allowlist."


@app.post("/")
async def guardrail(request: Request):
    try:
        body = await request.json()
    except Exception:
        return make_response("block", "Invalid JSON body.")

    tool = body.get("tool")

    if tool == "bash":
        command = body.get("command", "")
        decision, reason = check_bash(command)
        return make_response(decision, reason)

    if tool == "write_file":
        path = body.get("path", "")
        decision, reason = check_write_file(path)
        return make_response(decision, reason)

    if tool == "http_request":
        url = body.get("url", "")
        decision, reason = check_http_request(url)
        return make_response(decision, reason)

    return make_response("block", "Unknown tool type.")