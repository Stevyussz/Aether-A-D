"""Remote defense over SSH — audit & (opt-in) harden OUR OWN vulnbox from the laptop.

A&D boxes are remote containers reached by SSH. This connects with the operator's own key,
pulls the webroot, and runs the same read-only analysis the local defense does (source-sink
audit + web-shell scan), plus a privilege-escalation enumeration (SUID/sudo/cron) — so the
defender sees exactly what an attacker would use, in one command.

SAFETY:
- READ-ONLY by default: it only reads (tar the webroot, run enumeration). Nothing changes.
- Hardening is OPT-IN (``harden=True``) and bounded: strip SUID from NON-standard binaries
  (the privesc vector) and quarantine detected web shells. Each action is logged and reversible
  (``chmod u-s`` ↔ ``chmod u+s``; quarantine moves, never deletes). It never touches Apache,
  health.php/proof.php, or the flag file — SLA stays intact.
- It targets ONLY the box the operator points it at with their own credentials.
"""

from __future__ import annotations

import io
import shlex
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from ..core.logger import get_logger
from .source_audit import AuditFinding, SourceAuditor
from .webshell_scanner import WebshellHit, WebshellScanner

log = get_logger("remote_defense")

# Standard SUID-root binary names that are normal on a Linux box; anything else is a privesc
# suspect (e.g. a custom /usr/local/bin/syslog_viewer file-reader).
STD_SUID_NAMES: frozenset[str] = frozenset({
    "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount", "umount", "ping",
    "ping6", "pkexec", "fusermount", "fusermount3", "ssh-keysign", "chrome-sandbox",
    "snap-confine", "polkit-agent-helper-1", "unix_chkpwd", "at", "crontab", "expiry", "sg",
    "dbus-daemon-launch-helper", "vmware-authd", "Xorg.wrap", "pppd", "mount.nfs",
})

PRIVESC_ENUM: tuple[tuple[str, str], ...] = (
    ("whoami / id", "id"),
    ("sudo rights", "sudo -n -l 2>/dev/null"),
    ("SUID binaries", "find / -perm -4000 -type f 2>/dev/null"),
    ("SGID binaries", "find / -perm -2000 -type f 2>/dev/null"),
    ("capabilities", "getcap -r / 2>/dev/null | head -n 30"),
    ("cron", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d /etc/cron.hourly 2>/dev/null"),
    ("world-writable dirs", "find / -writable -type d 2>/dev/null | head -n 20"),
    ("flag env var", "printenv 2>/dev/null | grep -i 'flag\\|RSCTF'"),
)


@dataclass
class RemoteReport:
    connected: bool = False
    whoami: str = ""
    audit: list[AuditFinding] = field(default_factory=list)
    webshells: list[WebshellHit] = field(default_factory=list)
    suspect_suid: list[str] = field(default_factory=list)
    enum: dict[str, str] = field(default_factory=dict)
    hardened: list[str] = field(default_factory=list)
    error: str = ""


class RemoteDefense:
    """SSH-driven remote audit/harden of our own vulnbox."""

    def __init__(self, ssh_target: str | list[str], webroot: str = "/var/www/html",
                 timeout: float = 25.0) -> None:
        # ssh_target: the user's own ssh args, e.g. "6@10.0.0.1 -p 2222 -i ~/.ssh/key".
        self.ssh_args = ssh_target if isinstance(ssh_target, list) else shlex.split(ssh_target)
        self.webroot = webroot
        self.timeout = timeout

    def _ssh(self, remote_cmd: str, binary: bool = False):
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                "-o", "StrictHostKeyChecking=accept-new", *self.ssh_args, remote_cmd]
        try:
            p = subprocess.run(argv, capture_output=True, timeout=self.timeout,
                               text=not binary)
            return p.returncode, p.stdout, (p.stderr if not binary else b"")
        except subprocess.TimeoutExpired:
            return 255, (b"" if binary else ""), "timeout"
        except Exception as exc:  # noqa: BLE001
            return 255, (b"" if binary else ""), str(exc)

    def check_connection(self) -> tuple[bool, str]:
        rc, out, err = self._ssh("echo __AE_OK__; id")
        ok = isinstance(out, str) and "__AE_OK__" in out
        who = ""
        if ok:
            for line in out.splitlines():
                if line.startswith("uid="):
                    who = line.strip()
        return ok, who or (err or "ssh failed").strip()

    def _pull_source(self, dest: Path) -> bool:
        rc, out, err = self._ssh(
            f"tar czf - -C {shlex.quote(self.webroot)} . 2>/dev/null", binary=True)
        if not out:
            return False
        try:
            with tarfile.open(fileobj=io.BytesIO(out), mode="r:gz") as tf:
                for m in tf.getmembers():
                    # defense-in-depth: never let an absolute/.. member escape dest
                    name = m.name.lstrip("/")
                    if ".." in Path(name).parts:
                        continue
                    if m.isfile() or m.isdir():
                        tf.extract(m, dest)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("source tar extract failed", extra={"ctx": {"error": str(exc)}})
            return False

    def _enumerate(self) -> tuple[dict[str, str], list[str]]:
        enum: dict[str, str] = {}
        suspect: list[str] = []
        for label, cmd in PRIVESC_ENUM:
            rc, out, err = self._ssh(cmd)
            text = out if isinstance(out, str) else ""
            enum[label] = text.strip()
            if label == "SUID binaries":
                for line in text.splitlines():
                    path = line.strip()
                    if path and Path(path).name not in STD_SUID_NAMES:
                        suspect.append(path)
        return enum, suspect

    def audit(self, dest_dir: str | Path) -> RemoteReport:
        """Read-only: pull source, run source audit + webshell scan + privesc enum."""
        report = RemoteReport()
        ok, who = self.check_connection()
        report.connected, report.whoami = ok, who
        if not ok:
            report.error = who
            return report
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        if self._pull_source(dest):
            report.audit = SourceAuditor().audit_root(dest)
            report.webshells = WebshellScanner().scan_root(dest)
        report.enum, report.suspect_suid = self._enumerate()
        return report

    def harden(self, report: RemoteReport) -> list[str]:
        """OPT-IN, reversible: strip SUID from suspect binaries + quarantine web shells."""
        done: list[str] = []
        for binpath in report.suspect_suid:
            rc, out, err = self._ssh(f"chmod u-s {shlex.quote(binpath)} && echo OK")
            if isinstance(out, str) and "OK" in out:
                done.append(f"chmod u-s {binpath}")
        for hit in report.webshells:
            remote = f"{self.webroot.rstrip('/')}/{hit.path}"
            q = remote + ".ae_quarantine"
            rc, out, err = self._ssh(
                f"test -f {shlex.quote(remote)} && mv {shlex.quote(remote)} {shlex.quote(q)} && echo OK")
            if isinstance(out, str) and "OK" in out:
                done.append(f"quarantine {remote} -> {q}")
        report.hardened = done
        return done
