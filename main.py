from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pathlib import Path
from urllib.parse import urlparse, unquote
import os
import re

app = FastAPI()

WORKSPACE = Path("/home/agent/workspace").resolve()
FORBIDDEN_FILE = Path("/home/agent/service-account.json").resolve()
OUTBOX = Path("/data/agent/outbox").resolve()
ALLOWED_HOSTS = {"raw.githubusercontent.com", "api.github.com"}


def reply(decision: str, reason: str):
    return JSONResponse(content={"decision": decision, "reason": reason})


def expand_text(s: str) -> str:
    return unquote(os.path.expanduser(os.path.expandvars(s)))


def resolve_candidate_path(raw: str) -> Path:
    raw = expand_text(raw)
    p = Path(raw)
    if not p.is_absolute():
        p = WORKSPACE / p
    return p.resolve(strict=False)


def inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def bash_targets_forbidden_file(command: str) -> bool:
    text = expand_text(command)

    if str(FORBIDDEN_FILE) in text:
        return True

    tokens = re.findall(r'(?:(?:[A-Za-z]:)?[^\s"\']+)', text)
    for token in tokens:
        try:
            candidate = resolve_candidate_path(token)
            if candidate == FORBIDDEN_FILE:
                return True
        except Exception:
            pass

    return False


def check_bash(command: str):
    if bash_targets_forbidden_file(command):
        return "block", "Reading /home/agent/service-account.json is never permitted."
    return "allow", "Bash command is allowed."


def check_write_file(path: str):
    target = resolve_candidate_path(path)
    if not inside(target, OUTBOX):
        return "block", "Writes are only allowed inside /data/agent/outbox/."
    return "allow", "Write stays inside the allowed outbox directory."


def check_http_request(url: str):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        return "block", "Host is not in the exact allowlist."
    return "allow", "HTTP host is on the exact allowlist."


@app.post("/")
async def guardrail(request: Request):
    try:
        body = await request.json()
    except Exception:
        return reply("block", "Invalid JSON body.")

    tool = body.get("tool")

    if tool == "bash":
        return reply(*check_bash(body.get("command", "")))

    if tool == "write_file":
        return reply(*check_write_file(body.get("path", "")))

    if tool == "http_request":
        return reply(*check_http_request(body.get("url", "")))

    return reply("block", "Unknown tool type.")