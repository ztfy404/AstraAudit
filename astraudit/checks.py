"""Read-only checks for Astra Linux and compatible Debian-based systems."""
import os
import pwd
import re
import shutil
import stat
from pathlib import Path
from .core import Finding, read, register, service, sysctl


def result(id, category, title, status, detail, recommendation="", severity="medium"):
    return Finding(id, category, title, status, detail, recommendation, severity)


def perm(path, disallowed, id, title):
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return result(id,"permissions",title,"SKIP", "File unavailable: "+path)
    bad = bool(mode & disallowed)
    return result(id,"permissions",title,"FAIL" if bad else "PASS", 'Mode: {0:04o}'.format(mode),
                  "Review ownership and file permissions" if bad else "", "high")


def kernel(id, category, title, key, allowed):
    val = sysctl(key)
    if val is None:
        return result(id,category,title,"SKIP","Kernel setting unavailable")
    ok = val in allowed
    return result(id,category,title,"PASS" if ok else "WARN",'{0}={1}'.format(key, val),
                  "Review the recommended setting in the context of this host's workload" if not ok else "")


def ssh_values(ctx):
    executable = shutil.which("sshd") or "/usr/sbin/sshd"
    if not Path(executable).exists():
        return None
    rc, out = ctx.command([executable,"-T"])
    if rc != 0:
        return None
    keys = ("permitrootlogin","passwordauthentication","permitemptypasswords","maxauthtries")
    values = {}
    for key in keys:
        match = re.search(r"^" + key + r"\s+(\S+)$", out, re.M)
        if match:
            values[key] = match.group(1).lower()
    return values


@register("SYS-01","system","Operating system")
def system_name(c):
    data = read("/etc/os-release")
    if data is None:
        return result("SYS-01","system","Operating system","SKIP","Cannot read OS identity")
    return result("SYS-01","system","Operating system","INFO",
                  "Astra Linux detected" if "astra" in data.lower() else "Other Linux detected; some checks may not apply")


@register("SYS-02","system","Root filesystem available space")
def root_space(c):
    try:
        d = shutil.disk_usage("/")
        pct = 100*d.free/d.total
        status = "FAIL" if pct < 5 else "WARN" if pct < 10 else "PASS"
        return result("SYS-02","system","Root filesystem available space",status,'Free: {0:.1f}%'.format(pct),
                      "Investigate disk consumption" if status != "PASS" else "")
    except OSError:
        return result("SYS-02","system","Root filesystem available space","SKIP","Disk statistics unavailable")


@register("SYS-03","system","Current process umask")
def umask(c):
    text = read("/proc/self/status", 5000)
    match = re.search(r"^Umask:\s*([0-7]+)", text or "", re.M)
    if not match:
        return result("SYS-03","system","Current process umask","SKIP","/proc/self/status does not expose Umask")
    value = int(match.group(1), 8)
    ok = (value & 0o022) == 0o022
    return result("SYS-03","system","Current process umask","PASS" if ok else "WARN",'umask={0:03o}'.format(value),
                  "Prefer at least 022 for general-purpose accounts; 027/077 for sensitive roles" if not ok else "")


@register("SYS-04","system","Disk encryption inventory")
def luks(c):
    rc, out = c.command(["lsblk","-no","FSTYPE"])
    if rc != 0:
        return result("SYS-04","system","Disk encryption inventory","SKIP","lsblk unavailable")
    return result("SYS-04","system","Disk encryption inventory","INFO",
                  "At least one LUKS volume observed; root encryption not confirmed" if "crypto_LUKS" in out else
                  "No LUKS volumes detected; other encryption methods not assessed")


@register("ID-01","identity","Exactly one root UID")
def root_uid(c):
    try:
        users = [u for u in pwd.getpwall() if u.pw_uid == 0]
        ok = len(users)==1 and users[0].pw_name=="root"
        return result("ID-01","identity","Exactly one root UID","PASS" if ok else "FAIL",'UID 0 accounts: {0}'.format(len(users)),
                      "Investigate extra root-equivalent accounts", "high")
    except OSError:
        return result("ID-01","identity","Exactly one root UID","SKIP","User database unavailable")


@register("ID-02","identity","Empty password hashes")
def shadow(c):
    if not c.privileged:
        return result("ID-02","identity","Empty password hashes","SKIP","Requires sudo to read shadow metadata")
    raw = read("/etc/shadow", 500000)
    if raw is None:
        return result("ID-02","identity","Empty password hashes","SKIP","Cannot inspect shadow")
    count = sum(1 for row in raw.splitlines() if len(row.split(":"))>1 and row.split(":")[1]=="")
    return result("ID-02","identity","Empty password hashes","FAIL" if count else "PASS",
                  'Empty password hash fields: {0}'.format(count),"Review and disable passwordless accounts", "high")


@register("ID-03","identity","Sudo NOPASSWD entries")
def sudo_nopass(c):
    paths=[Path("/etc/sudoers")]
    if Path("/etc/sudoers.d").is_dir():
        paths.extend(x for x in Path("/etc/sudoers.d").iterdir() if x.is_file())
    readable = 0; count=0
    for path in paths:
        data=read(str(path), 100000)
        if data is None: continue
        readable+=1
        count+=sum(1 for ln in data.splitlines() if not ln.lstrip().startswith("#") and "NOPASSWD:" in ln)
    if not readable:
        return result("ID-03","identity","Sudo NOPASSWD entries","SKIP","Cannot read sudo policy")
    return result("ID-03","identity","Sudo NOPASSWD entries","WARN" if count else "PASS",
                  'Uncommented passwordless-sudo directives: {0}'.format(count),"Review exceptions manually" if count else "")


@register("ID-04","identity","Default password aging")
def password_age(c):
    data=read("/etc/login.defs")
    if data is None:
        return result("ID-04","identity","Default password aging","SKIP","/etc/login.defs unreadable")
    m=re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)",data,re.M)
    return result("ID-04","identity","Default password aging","INFO",
                  'PASS_MAX_DAYS={0} (new accounts only)'.format(m.group(1)) if m else "PASS_MAX_DAYS not set")


@register("PERM-01","permissions","/etc/passwd permissions")
def passwd(c): return perm("/etc/passwd",0o022,"PERM-01","/etc/passwd permissions")

@register("PERM-02","permissions","/etc/shadow permissions")
def shadow_mode(c): return perm("/etc/shadow",0o027,"PERM-02","/etc/shadow permissions")

@register("PERM-03","permissions","/etc/sudoers permissions")
def sudo_mode(c): return perm("/etc/sudoers",0o137,"PERM-03","/etc/sudoers permissions")

@register("PERM-04","permissions","SSH configuration permissions")
def ssh_mode(c): return perm("/etc/ssh/sshd_config",0o022,"PERM-04","SSH configuration permissions")


@register("PERM-05","permissions","World-writable entries under /etc")
def world_etc(c):
    try:
        names=list(Path("/etc").iterdir())
        n=sum(1 for x in names if not x.is_symlink() and x.lstat().st_mode & stat.S_IWOTH)
        return result("PERM-05","permissions","World-writable entries under /etc", "FAIL" if n else "PASS",
                      'World-writable direct children of /etc: {0}'.format(n), "Inspect and restrict world-write permissions" if n else "", "high")
    except OSError:
        return result("PERM-05","permissions","World-writable entries under /etc","SKIP","Cannot list /etc")


@register("PERM-06","permissions","Current home directory permissions")
def home_mode(c):
    try:
        home=Path(pwd.getpwuid(os.getuid()).pw_dir)
        mode=stat.S_IMODE(home.stat().st_mode)
        bad=bool(mode & 0o002)
        return result("PERM-06","permissions","Current home directory permissions","WARN" if bad else "PASS",
                      'Home directory mode: {0:04o}'.format(mode), "Remove world-write access" if bad else "")
    except (OSError,KeyError):
        return result("PERM-06","permissions","Current home directory permissions","SKIP","Home directory unavailable")


@register("KERN-01","kernel","Address Space Layout Randomization")
def aslr(c):
    val=sysctl("kernel.randomize_va_space")
    if val is None: return result("KERN-01","kernel","Address Space Layout Randomization","SKIP","Setting unavailable")
    return result("KERN-01","kernel","Address Space Layout Randomization",
                  "PASS" if val==2 else "FAIL" if val==0 else "WARN",'ASLR={0}'.format(val),
                  "Use ASLR 2 unless there is a tested compatibility exception" if val !=2 else "", "high")


@register("KERN-02","kernel","Protected hardlinks")
def hardlinks(c):return kernel("KERN-02","kernel","Protected hardlinks","fs.protected_hardlinks",{1})

@register("KERN-03","kernel","Protected symlinks")
def symlinks(c):return kernel("KERN-03","kernel","Protected symlinks","fs.protected_symlinks",{1})

@register("KERN-04","kernel","Restrict exposed kernel pointers")
def kptr(c):return kernel("KERN-04","kernel","Restrict exposed kernel pointers","kernel.kptr_restrict",{1,2})

@register("KERN-05","kernel","Restrict unprivileged dmesg")
def dmesg(c):return kernel("KERN-05","kernel","Restrict unprivileged dmesg","kernel.dmesg_restrict",{1})

@register("KERN-06","kernel","Restrict unprivileged BPF")
def bpf(c):return kernel("KERN-06","kernel","Restrict unprivileged BPF","kernel.unprivileged_bpf_disabled",{1,2})


@register("NET-01","network","TCP SYN cookies")
def syncookies(c):return kernel("NET-01","network","TCP SYN cookies","net.ipv4.tcp_syncookies",{1})

@register("NET-02","network","Reject ICMP redirects")
def redirects(c):return kernel("NET-02","network","Reject ICMP redirects","net.ipv4.conf.all.accept_redirects",{0})

@register("NET-03","network","Reject source-routed packets")
def sourceroute(c):return kernel("NET-03","network","Reject source-routed packets","net.ipv4.conf.all.accept_source_route",{0})

@register("NET-04","network","Reverse path filtering")
def rpfilter(c):return kernel("NET-04","network","Reverse path filtering","net.ipv4.conf.all.rp_filter",{1,2})

@register("NET-05","network","IP forwarding review")
def ipforward(c):
    val=sysctl("net.ipv4.ip_forward")
    if val is None:return result("NET-05","network","IP forwarding review","SKIP","Setting unavailable")
    return result("NET-05","network","IP forwarding review","PASS" if val==0 else "WARN",
                  'IPv4 forwarding={0}'.format(val),"Verify routing is intentional (may be needed for Docker, gateways)")


@register("NET-06","network","Host firewall")
def firewall(c):
    if shutil.which("ufw"):
        rc,out=c.command(["ufw","status"])
        if rc==0 and re.search(r"^Status:\s+active",out,re.M):
            return result("NET-06","network","Host firewall","PASS","UFW active (rules not evaluated)")
    if not c.privileged:
        return result("NET-06","network","Host firewall","SKIP","Run with sudo for firewall inspection")
    if shutil.which("nft"):
        rc,out=c.command(["nft","list","ruleset"])
        if rc==0 and re.search(r"\bhook\s+input\b",out):
            return result("NET-06","network","Host firewall","INFO","nftables input chain present; policy requires manual review")
    if shutil.which("iptables"):
        rc,out=c.command(["iptables","-S","INPUT"])
        if rc==0:
            return result("NET-06","network","Host firewall","PASS" if "-P INPUT DROP" in out else "INFO",
                          "iptables INPUT default-drop policy" if "-P INPUT DROP" in out else "iptables rules present; effectiveness unverified")
    return result("NET-06","network","Host firewall","WARN","No active firewall verified","Review local firewall policy")


def listeners(c):
    rc,out=c.command(["ss","-H","-lnt"])
    return [ln.split()[3] for ln in out.splitlines() if len(ln.split())>=4] if rc==0 else None


def wildcard(sock):return sock.startswith(("0.0.0.0:","[::]:","*:",":::"))


@register("NET-07","network","TCP listening exposure")
def sockets(c):
    vals=listeners(c)
    if vals is None:return result("NET-07","network","TCP listening exposure","SKIP","ss unavailable")
    return result("NET-07","network","TCP listening exposure","INFO",
                  'Listening TCP sockets: {0}; wildcard-bound: {1}'.format(len(vals), sum(map(wildcard, vals))),
                  "Review exposed ports; no network scanning is performed")


@register("SSH-01","ssh","SSH service inventory")
def ssh_service(c):
    if not Path("/usr/sbin/sshd").exists() and not shutil.which("sshd"):
        return result("SSH-01","ssh","SSH service inventory","INFO","OpenSSH server not installed")
    a,_=service(c,"ssh.service")
    b,_=service(c,"sshd.service")
    return result("SSH-01","ssh","SSH service inventory","INFO",'Service: {0}'.format('active' if 'active' in (a, b) else a))


@register("SSH-02","ssh","Disable root SSH login")
def ssh_root(c):return ssh_rule(c,"SSH-02","Disable root SSH login","permitrootlogin",lambda v:v=="no", "Consider PermitRootLogin no")

@register("SSH-03","ssh","Disallow empty SSH passwords")
def ssh_empty(c):return ssh_rule(c,"SSH-03","Disallow empty SSH passwords","permitemptypasswords",lambda v:v=="no","Set PermitEmptyPasswords no",bad="FAIL")

@register("SSH-04","ssh","SSH password login policy")
def ssh_password(c):return ssh_rule(c,"SSH-04","SSH password login policy","passwordauthentication",lambda v:v=="no","Consider key authentication after verifying recovery access")

@register("SSH-05","ssh","SSH authentication attempt limit")
def ssh_attempts(c):return ssh_rule(c,"SSH-05","SSH authentication attempt limit","maxauthtries",lambda v:v.isdigit() and int(v)<=6,"Consider MaxAuthTries <= 6")


def ssh_rule(c,id,title,key,predicate,recommendation,bad="WARN"):
    vals=ssh_values(c)
    if vals is None or key not in vals:
        return result(id,"ssh",title,"SKIP","sshd -T unavailable; effective settings not verified")
    val=vals[key]
    return result(id,"ssh",title,"PASS" if predicate(val) else bad,
                  '{0}={1}'.format(key, val), "" if predicate(val) else recommendation)


@register("LOG-01","logging","Audit daemon running")
def auditd(c):
    state,_=service(c,"auditd.service")
    return result("LOG-01","logging","Audit daemon running",
                  "PASS" if state=="active" else "WARN" if state=="inactive" else "SKIP",
                  'auditd={0}'.format(state), "Review auditd setup" if state=="inactive" else "")


@register("LOG-02","logging","Loaded audit rules")
def audit_rules(c):
    if not c.privileged:return result("LOG-02","logging","Loaded audit rules","SKIP","Requires sudo")
    rc,out=c.command(["auditctl","-l"])
    if rc!=0:return result("LOG-02","logging","Loaded audit rules","SKIP","auditctl unavailable or disabled")
    count=sum(1 for ln in out.splitlines() if ln.strip() and "No rules" not in ln)
    return result("LOG-02","logging","Loaded audit rules","PASS" if count else "WARN",
                  'Rule lines loaded: {0}'.format(count),"Review audit policy if no rules configured" if count==0 else "")


@register("LOG-03","logging","Persistent journal")
def journal(c):
    if not Path("/run/systemd/system").exists():
        return result("LOG-03","logging","Persistent journal","SKIP","No systemd runtime")
    enabled=Path("/var/log/journal").is_dir()
    return result("LOG-03","logging","Persistent journal","INFO",
                  "Persistent journal directory exists" if enabled else "No persistent journald directory; syslog may provide persistence")


@register("LOG-04","logging","System log service")
def syslog(c):
    names=[x for x in ("rsyslog","syslog-ng") if service(c,x+".service")[0]=="active"]
    return result("LOG-04","logging","System log service","PASS" if names else "INFO",
                  "Active syslog services: "+(", ".join(names) if names else "none detected (journald may be used)"))


@register("LOG-05","logging","Log rotation utility")
def rotate(c):
    present=bool(shutil.which("logrotate") or Path("/usr/sbin/logrotate").exists())
    return result("LOG-05","logging","Log rotation utility","PASS" if present else "WARN",
                  "logrotate present" if present else "logrotate unavailable","Review retention and rotation" if not present else "")


@register("PKG-01","packages","Package database consistency")
def dpkg(c):
    rc,out=c.command(["dpkg","--audit"])
    if rc!=0:return result("PKG-01","packages","Package database consistency","SKIP","dpkg unavailable")
    bad=bool(out.strip())
    return result("PKG-01","packages","Package database consistency","WARN" if bad else "PASS",
                  "dpkg reports unfinished operations" if bad else "No incomplete dpkg operations", "Inspect dpkg --audit locally" if bad else "")


@register("PKG-02","packages","Packages with cached updates")
def apt_upgrades(c):
    rc,out=c.command(["apt","list","--upgradable"],timeout=10)
    if rc!=0:return result("PKG-02","packages","Packages with cached updates","SKIP","APT unavailable")
    count=sum(1 for ln in out.splitlines() if "upgradable from:" in ln)
    return result("PKG-02","packages","Packages with cached updates","WARN" if count else "INFO",
                  'Cached upgradable packages: {0}. APT cache was not refreshed.'.format(count),
                  "Run apt update manually to determine current available updates")


@register("PKG-03","packages","APT repository transport")
def repo_transport(c):
    paths=[Path("/etc/apt/sources.list")]
    root=Path("/etc/apt/sources.list.d")
    if root.is_dir():paths += list(root.glob("*.list"))+list(root.glob("*.sources"))
    seen=0; http=0
    for p in paths:
        data=read(str(p),120000)
        if not data:continue
        for ln in data.splitlines():
            ln=ln.strip()
            if ln.startswith("deb ") or ln.startswith("deb-src ") or ln.startswith("URIs:"):
                seen+=1;http+=int("http://" in ln)
    return result("PKG-03","packages","APT repository transport","INFO" if seen==0 else "WARN" if http else "PASS",
                  'Active source lines: {0}; plain HTTP lines: {1}'.format(seen, http),
                  "Prefer HTTPS when available; ensure APT signatures are always checked" if http else "")


@register("SEC-01","security_modules","Kernel LSM inventory")
def lsm(c):
    data=read("/sys/kernel/security/lsm",1000)
    return result("SEC-01","security_modules","Kernel LSM inventory","INFO" if data else "SKIP",
                  "LSM modules: "+data.strip() if data else "LSM inventory unavailable")


@register("SEC-02","security_modules","AppArmor status")
def apparmor(c):
    data=read("/sys/module/apparmor/parameters/enabled",10)
    return result("SEC-02","security_modules","AppArmor status","INFO",
                  "AppArmor kernel support enabled (profiles not validated)" if data and data.strip().upper()=="Y"
                  else "AppArmor kernel status not enabled or unavailable; edition-specific")


@register("SEC-03","security_modules","Astra PARSEC inventory")
def parsec(c):
    found=Path("/parsecfs").exists() or Path("/etc/parsec").exists()
    return result("SEC-03","security_modules","Astra PARSEC inventory","INFO",
                  "PARSEC-related paths detected; security policy not evaluated" if found else
                  "PARSEC paths absent; may be normal for Astra Common Edition")


@register("SEC-04","security_modules","Time synchronization daemon")
def ntp(c):
    active=[s for s in ("systemd-timesyncd","chrony","ntp","ntpd") if service(c,s+".service")[0]=="active"]
    if not Path("/run/systemd/system").exists():
        return result("SEC-04","security_modules","Time synchronization daemon","SKIP","No systemd runtime")
    return result("SEC-04","security_modules","Time synchronization daemon","PASS" if active else "WARN",
                  "Active time sync services: "+(", ".join(active) if active else "none detected"),
                  "Check NTP/chrony configuration" if not active else "")


@register("APP-01","applications","Database TCP exposure")
def db_exposure(c):
    vals=listeners(c)
    if vals is None:return result("APP-01","applications","Database TCP exposure","SKIP","ss unavailable")
    ports=sorted(set(x.rsplit(":",1)[-1] for x in vals if wildcard(x) and x.rsplit(":",1)[-1] in ("3306","5432")))
    return result("APP-01","applications","Database TCP exposure","WARN" if ports else "PASS",
                  "Wildcard-bound database ports: "+(", ".join(ports) if ports else "none of 3306/5432"),
                  "Review DB bind-address and firewall policy" if ports else "")


@register("APP-02","applications","Database configuration directory writable access")
def db_cfg(c):
    paths=[Path(p) for p in ("/etc/mysql/my.cnf","/etc/mysql/mariadb.conf.d/50-server.cnf","/etc/postgresql") if Path(p).exists()]
    if not paths:return result("APP-02","applications","Database configuration directory writable access","SKIP","No standard database config paths")
    bad=sum(1 for p in paths if p.stat().st_mode & stat.S_IWOTH)
    return result("APP-02","applications","Database configuration directory writable access","WARN" if bad else "PASS",
                  'Inspected paths: {0}; world-writable: {1}'.format(len(paths), bad))


@register("APP-03","applications","Docker socket permissions")
def docker(c):
    path=Path("/var/run/docker.sock")
    if not path.exists():return result("APP-03","applications","Docker socket permissions","INFO","Docker socket absent")
    try:
        mode=stat.S_IMODE(path.stat().st_mode)
        return result("APP-03","applications","Docker socket permissions","FAIL" if mode & 0o002 else "INFO",
                      'Docker socket mode: {0:04o} (membership not checked)'.format(mode),"Never expose socket as world-writable")
    except OSError:
        return result("APP-03","applications","Docker socket permissions","SKIP","Docker socket inaccessible")