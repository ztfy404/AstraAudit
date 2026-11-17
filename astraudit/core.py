"""Read-only audit primitives. No network calls or shell execution."""

import datetime as dt
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

VERSION = "0.1.1"
STATUSES = {"PASS", "WARN", "FAIL", "INFO", "SKIP"}


class Finding(object):
    """Individual audit finding. Python 3.5-compatible data class."""

    def __init__(self, id, category, title, status, detail,
                 recommendation="", severity="medium"):
        if status not in STATUSES:
            raise ValueError("invalid status: " + status)
        self.id = id
        self.category = category
        self.title = title
        self.status = status
        self.detail = detail
        self.recommendation = recommendation
        self.severity = severity

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "severity": self.severity,
        }


class Context(object):
    def __init__(self, privileged, timeout=5.0):
        self.privileged = privileged
        self.timeout = timeout

    def command(self, args, timeout=None):
        """Execute fixed program with no shell, bounded time and output."""
        if not shutil.which(args[0]):
            return None, "program missing"
        try:
            env = dict(os.environ, LC_ALL="C", LANG="C")
            result = subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout or self.timeout, env=env, check=False
            )
            output = (result.stdout + b"\n" + result.stderr)
            return result.returncode, output[:12000].decode("utf-8", "replace").strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, type(exc).__name__


def read(path, limit=16000):
    try:
        with open(path, encoding="utf-8", errors="replace") as stream:
            return stream.read(limit)
    except (OSError, UnicodeError):
        return None


def sysctl(key):
    value = read("/proc/sys/" + key.replace(".", "/"), 100)
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def service(ctx, name):
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


def finding(id, category, title, status, detail,
            recommendation="", severity="medium"):
    return Finding(id, category, title, status, detail, recommendation, severity)


CHECKS = []


def register(id, category, title):
    def deco(fn):
        CHECKS.append((id, category, title, fn))
        return fn
    return deco


def sanitize_one_line(text, maxlen=160):
    return re.sub(r"[\r\n\t]+", " ", text).strip()[:maxlen]


def summary(findings):
    counts = {s: 0 for s in ("PASS", "WARN", "FAIL", "INFO", "SKIP")}
    for item in findings:
        counts[item.status] += 1
    assessed = counts["PASS"] + counts["WARN"] + counts["FAIL"]
    counts["assessed"] = assessed
    counts["passed_percent"] = round(100 * counts["PASS"] / assessed, 1) if assessed else None
    return counts


def document(findings, selected_categories):
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
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": dict(info, kernel=platform.release()[:80], architecture=platform.machine()),
        "privileged": bool(hasattr(os, "geteuid") and os.geteuid() == 0),
        "categories": selected_categories,
        "summary": summary(findings),
        "findings": [x.to_dict() for x in findings],
        "note": "Local, point-in-time, non-invasive checks. Not a compliance certification.",
    }