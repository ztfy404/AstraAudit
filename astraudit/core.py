"""Read-only audit primitives. No network calls or shell execution."""
from __future__ import annotations

import dataclasses
import datetime as dt
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, List, Optional, Tuple

VERSION = "0.1.0"
STATUSES = {"PASS", "WARN", "FAIL", "INFO", "SKIP"}


@dataclasses.dataclass
class Finding:
    id: str
    category: str
    title: str
    status: str
    detail: str
    recommendation: str = ""
    severity: str = "medium"

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError("invalid status: " + self.status)

    def to_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Context:
    privileged: bool
    timeout: float = 5.0

    def command(self, args: List[str], timeout: Optional[float] = None) -> Tuple[Optional[int], str]:
        """Call fixed program with explicit arguments and bounded output; no shell."""
        if not shutil.which(args[0]):
            return None, "program missing"
        try:
            env = dict(os.environ, LC_ALL="C", LANG="C")
            result = subprocess.run(args, capture_output=True, text=True, errors="replace",
                                    timeout=timeout or self.timeout, env=env, check=False)
            return result.returncode, (result.stdout + "\n" + result.stderr)[:12000].strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, type(exc).__name__


def read(path: str, limit: int = 16000) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as stream:
            return stream.read(limit)
    except (OSError, UnicodeError):
        return None


def sysctl(key: str) -> Optional[int]:
    value = read("/proc/sys/" + key.replace(".", "/"), 100)
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def service(ctx: Context, name: str) -> Tuple[str, str]:
    if not shutil.which("systemctl") or not Path("/run/systemd/system").exists():
        return "unavailable", "systemd unavailable"
    rc, out = ctx.command(["systemctl", "is-active", name])
    if rc is None:
        return "unavailable", out
    if rc == 0 and out.strip() == "active":
        return "active", "active"
    if out.strip() in ("inactive", "failed", "activating", "deactivating"):
        return "inactive", out.strip()
    if "not-found" in out or "could not be found" in out or "not loaded" in out:
        return "missing", "not installed"
    return "unavailable", out[:80]


def finding(id: str, category: str, title: str, status: str, detail: str,
            recommendation: str = "", severity: str = "medium") -> Finding:
    return Finding(id, category, title, status, detail, recommendation, severity)


CHECKS = []


def register(id: str, category: str, title: str):
    def deco(fn: Callable[[Context], Finding]):
        CHECKS.append((id, category, title, fn))
        return fn
    return deco


def sanitize_one_line(text: str, maxlen: int = 160) -> str:
    return re.sub(r"[\r\n\t]+", " ", text).strip()[:maxlen]


def summary(findings: List[Finding]):
    counts = {s: 0 for s in ("PASS", "WARN", "FAIL", "INFO", "SKIP")}
    for item in findings:
        counts[item.status] += 1
    assessed = counts["PASS"] + counts["WARN"] + counts["FAIL"]
    counts["assessed"] = assessed
    counts["passed_percent"] = round(100 * counts["PASS"] / assessed, 1) if assessed else None
    return counts


def document(findings: List[Finding], selected_categories: List[str]):
    info = {}
    data = read("/etc/os-release", 16000) or ""
    for key in ("ID", "VERSION_ID", "PRETTY_NAME"):
        match = re.search(r"^" + key + r"=(.*)$", data, re.MULTILINE)
        if match:
            info[key.lower()] = match.group(1).strip('"')[:90]
    # Never publish hostname, account names, IPs, password hashes or full command output.
    return {
        "tool": "AstraAudit",
        "version": VERSION,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "platform": {**info, "kernel": platform.release()[:80], "architecture": platform.machine()},
        "privileged": bool(hasattr(os, "geteuid") and os.geteuid() == 0),
        "categories": selected_categories,
        "summary": summary(findings),
        "findings": [x.to_dict() for x in findings],
        "note": "Local, point-in-time, non-invasive checks. Not a compliance certification.",
    }