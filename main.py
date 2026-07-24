from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pathlib import Path
from urllib.parse import urlparse, unquote
import os
import re

app = FastAPI()

FORBIDDEN_FILE = Path("/home/agent/service-account.json").resolve()
OUTBOX = Path("/data/agent/outbox").resolve()
ALLOWED_HOSTS = {"raw.githubusercontent.com", "api.github.com"}


def reply(decision: str, reason: str):
    return JSONResponse(content={"decision": decision, "reason": reason})


def expand_shellish(text: str) -> str:
    text = os.path.expandvars(text)
    text = os.path.expanduser(text)
    text = unquote(text)
    return text


def resolve_like_path(p: str) -> Path:
    p = expand_shellish(p)
    path = Path(p)
    if not path.is_absolute():
        path = Path("/home/agent/workspace") / path
    return path.resolve(strict=False)


def is_under(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def bash_blocks_secret(command: str) -> bool:
    text = expand_shellish(command)
    if str(FORBIDDEN_FILE) in text:
        return True
    if "service-account.json" in text:
        return True

    candidates = re.findall(r"[/~$A-Za-z0-9_\-./{}]+", text)
    for c in candidates:
        try:
            rp = resolve_like_path(c)
            if rp == FORBIDDEN_FILE:
                return True
        except Exception:
            pass
    return False


def check_bash(command: str):
    if bash_blocks_secret(command):
        return "block", "Reading /home/agent/service-account.json is never permitted."
    return "allow", "Bash command is allowed."


def check_write_file(path: str):
    final_path = resolve_like_path(path)
    if not is_under(final_path, OUTBOX):
        return "block", "Writes are only allowed inside /data/agent/outbox/."
    return "allow", "Write stays inside the allowed outbox directory."


def check_http_request(url: str):
    try:
        host = urlparse(url).hostname
    except Exception:
        return "block", "Invalid URL."

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