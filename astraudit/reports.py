"""Reports never embed raw commands, passwords, usernames or IP addresses."""
import html
import json
import os
from pathlib import Path


def markdown(doc):
    stats=doc["summary"]
    lines=["# AstraAudit security assessment", "",
           "**UTC:** " + doc["created_utc"],
           "**OS:** " + doc["platform"].get("pretty_name", "unknown"),
           "**Kernel:** " + doc["platform"]["kernel"],
           "**Privileged:** " + str(doc["privileged"]), "",
           "## Summary", "",
           " | ".join("%s: %s"%(key,stats[key]) for key in ("PASS","WARN","FAIL","INFO","SKIP")),"",
           "Passed among assessed: **%s** (not a security compliance score)"%(
               str(stats["passed_percent"])+"%" if stats["passed_percent"] is not None else "N/A"),"",
           "## Findings", ""]
    for item in doc["findings"]:
        lines.append("### %s · %s · %s"%(item["id"],item["status"],item["title"]))
        lines.extend(["", "Category: **%s** · Severity: **%s**"%(item["category"],item["severity"]),"",
                      item["detail"].replace("\n"," "), ""])
        if item["recommendation"]:
            lines.extend(["**Review:** "+item["recommendation"].replace("\n"," "),""])
    lines.extend(["---", "", "This is a read-only, point-in-time baseline, not a CIS/GOST/FSTEK certificate.",
                  "Review the report before sharing. Check outputs against local security policy.", ""])
    return "\n".join(lines)


def html_report(doc):
    esc=lambda value:html.escape(str(value),quote=True)
    color={"PASS":"#198754","WARN":"#cc8b00","FAIL":"#c64141","INFO":"#457ac6","SKIP":"#777"}
    cards=[]
    for f in doc["findings"]:
        cards.append('<section class="finding"><div class="head"><span class="pill" style="background:%s">%s</span> <b>%s · %s</b></div><p>%s</p>%s</section>'%(
            color[f["status"]],esc(f["status"]),esc(f["id"]),esc(f["title"]),esc(f["detail"]),
            '<small>Recommendation: '+esc(f["recommendation"])+"</small>" if f["recommendation"] else ""))
    counts=doc["summary"]
    tiles="".join('<div class="tile"><strong>%s</strong><span>%s</span></div>'%(counts[s],s) for s in ("PASS","WARN","FAIL","INFO","SKIP"))
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AstraAudit security assessment</title><style>
:root{color-scheme:light dark}body{font:16px/1.5 system-ui,Segoe UI,sans-serif;max-width:990px;padding:30px 20px;margin:auto;background:#f7f8fb;color:#15202b}header{padding:30px;border-radius:16px;background:#19283b;color:white}h1{margin:0 0 8px}.muted{opacity:.74}.stats{display:flex;gap:12px;flex-wrap:wrap;margin:25px 0}.tile{background:white;border-radius:12px;min-width:95px;flex:1;padding:16px;text-align:center;border:1px solid #ddd}.tile strong{display:block;font-size:28px}.tile span{font-size:12px}.finding{background:white;padding:18px 22px;margin:13px 0;border:1px solid #ddd;border-radius:12px}.finding p{margin:10px 0}.pill{color:white;padding:4px 9px;border-radius:8px;font-size:12px;font-weight:700}.head{display:flex;align-items:center;gap:10px}small{color:#52616f}footer{margin:30px 0;color:#5d6774;font-size:12px}@media(prefers-color-scheme:dark){body{background:#101721;color:#edf0f5}.tile,.finding{background:#1b2734;border-color:#3c4857}small,footer{color:#c0ccd9}}</style></head><body>
<header><h1>AstraAudit</h1><div class="muted">Local security assessment · %s · %s</div></header>
<div class="stats">%s</div><p>Assessed checks passing: <strong>%s</strong>. This is not a compliance or security rating.</p>
<h2>Checks</h2>%s<footer>Read-only baseline. No active exploit tests, no modification of system settings. Review report before sharing publicly.</footer></body></html>'''%(
    esc(doc["platform"].get("pretty_name","Linux")),esc(doc["created_utc"]),tiles,
    esc(counts["passed_percent"]),"".join(cards))


def write_reports(output, document, formats):
    target=Path(output).expanduser().resolve()
    if not target.exists():
        target.mkdir(parents=True,mode=0o700)
    if not target.is_dir():
        raise OSError("Output must be a directory")
    # The directory may be user supplied with broader permissions: keep files private.
    from datetime import datetime, timezone
    from uuid import uuid4
    stem="astraaudit-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")+"-"+uuid4().hex[:6]
    content={"json":json.dumps(document,indent=2,ensure_ascii=False)+"\n",
             "md":markdown(document),"html":html_report(document)}
    paths=[]
    for extension in formats:
        filepath=target / (stem+"."+extension)
        # Exclusive creation and 0600 prevent accidental overwrites/other-user reading.
        fd=os.open(str(filepath),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as stream:
            stream.write(content[extension])
        paths.append(filepath)
    return paths