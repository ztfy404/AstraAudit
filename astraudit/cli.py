"""Main user-facing command line interface."""
import argparse
import os
import sys

from .core import CHECKS, Context, VERSION, document
from . import checks  # register built-in checks
from .reports import write_reports


def parser():
    p=argparse.ArgumentParser(prog="astraaudit",description="Read-only Astra Linux security baseline")
    p.add_argument("action",nargs="?",choices=("run","list","version"),default="run")
    p.add_argument("--output",default="./reports",help="Local output folder (default: ./reports)")
    p.add_argument("--category",action="append",default=[],help="Category, may be repeated")
    p.add_argument("--format",default="json,md,html",help="Comma-separated: json,md,html")
    p.add_argument("--strict",action="store_true",help="Return exit code 2 if any FAIL checks")
    return p


def main(argv=None):
    args=parser().parse_args(argv)
    if args.action=="version":
        print("AstraAudit",VERSION)
        return 0
    if args.action=="list":
        for id, category, title, _ in CHECKS:
            print("%s  %-18s %s"%(id,category,title))
        return 0
    categories=sorted(set(item[1] for item in CHECKS))
    unknown=set(args.category)-set(categories)
    if unknown:
        parser().error("Unknown categories: "+", ".join(sorted(unknown))+"; available: "+", ".join(categories))
    formats=[x.strip() for x in args.format.split(",") if x.strip()]
    if not formats or any(x not in ("json","md","html") for x in formats):
        parser().error("--format must contain json, md, or html")
    formats=list(dict.fromkeys(formats))
    chosen=args.category or categories
    context=Context(privileged=hasattr(os,"geteuid") and os.geteuid()==0)
    findings=[]
    selected=[row for row in CHECKS if row[1] in chosen]
    print("AstraAudit %s | %d checks | read-only | no network requests"%(VERSION,len(selected)))
    for id, category, title, callback in selected:
        try:
            item=callback(context)
        except Exception as exc:
            from .core import Finding
            item=Finding(id,category,title,"SKIP","Check raised "+type(exc).__name__+"; manual review required")
        findings.append(item)
        print("[%-4s] %-8s %s"%(item.status,id,item.title))
    doc=document(findings,sorted(set(chosen)))
    try:
        locations=write_reports(args.output,doc,formats)
    except OSError as exc:
        print("Cannot save reports: "+str(exc),file=sys.stderr)
        return 3
    counts=doc["summary"]
    print("Results: PASS={PASS}, WARN={WARN}, FAIL={FAIL}, INFO={INFO}, SKIP={SKIP}".format(**counts))
    for location in locations:
        print("Report:",location)
    return 2 if args.strict and counts["FAIL"] else 0