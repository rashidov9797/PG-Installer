
# PostgreSQL Installer for Rocky Linux 8

An automated Python script to install and configure **PostgreSQL (Versions 13-18)** on Rocky Linux 8.

This script handles PGDG repositories, dependencies (EPEL/PowerTools), SELinux contexts, and basic configuration, providing a ready-to-use database managed via `pg_ctl`.

## 🚀 Features

* **Multi-Version Support:** Install PostgreSQL 13, 14, 15, 16, 17, or 18.
* **Automated Setup:** Handles `dnf` modules, EPEL, PowerTools, and PGDG repos automatically.
* **Customization:** You can define a custom `PGDATA` directory and Port.
* **SELinux Support:** Automatically applies correct SELinux contexts for custom data directories.
* **Detailed Reporting:** Generates a full installation report (CPU, RAM, Disk, Version) in `/home/postgres/installer_log/`.

## 📋 Prerequisites

* **OS:** Rocky Linux 8 (or RHEL 8 / AlmaLinux 8).
* **User:** Must be run as **root**.
* **Internet:** Required to download packages.

## 🛠️ Usage

1. Create the script file (e.g., `install_pg.py`) and paste the code below.
2. Run the script:

    ```bash
    sudo python3 install_pg.py
    ```

3. Follow the interactive prompts:
    * Select Version (13-18).
    * Set Data Directory.
    * Set Port.

## 📝 Post-Installation

The script sets up the environment for the `postgres` user. To manage your database:

```bash
# Switch to postgres user

The installer sets up the database, but you should manually configure the environment $PGHOME, $PGBIN, $PATH variables for the `postgres` user to use commands globally.
su - postgres

# Check status
pg_ctl -D $PGDATA status

# Stop / Start / Restart
pg_ctl -D $PGDATA stop
pg_ctl -D $PGDATA start
pg_ctl -D $PGDATA restart

# Connect via SQL
psql -p $PGPORT
```

## 📂 Logs & Reports

* **Installation Report:** `/home/postgres/installer_log/`
  * Contains system details (CPU, RAM, Disk) and installation status.
* **Database Logs:** `$PGDATA/log/`
  * Contains PostgreSQL runtime logs (errors, warnings, startups).

---

## 🐍 The Python Script

Copy the source code below and save it as `install_pg.py`.

```python


#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import shutil
import subprocess
from datetime import datetime

MIN_VER = 13
MAX_VER = 18

# Final report location
REPORT_BASE_DIR = "/home/postgres/installer_log"
SEP_WIDTH = 80


def die(msg, code=1):
    print("\n[ERROR] " + msg, file=sys.stderr)
    sys.exit(code)


def sep_line(char="-", width=SEP_WIDTH):
    return char * width


def print_block(title, lines=None, char="-"):
    print(sep_line(char))
    print(title)
    print(sep_line(char))
    if lines:
        for ln in lines:
            print(ln)
    print()


def run(cmd, check=True, capture=False):
    print("\n[RUN] " + " ".join(cmd))
    if capture:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        if check and p.returncode != 0:
            print(p.stdout)
            die("Command failed: " + " ".join(cmd))
        return p.stdout
    else:
        p = subprocess.run(cmd)
        if check and p.returncode != 0:
            die("Command failed: " + " ".join(cmd))
        return None


def is_root():
    return os.geteuid() == 0


def prompt(text, default=None, validator=None, allow_blank=False):
    while True:
        if default is not None:
            raw = input(f"{text} [{default}]: ").strip()
            if raw == "":
                if allow_blank:
                    return ""
                raw = str(default)
        else:
            raw = input(f"{text}: ").strip()
            if raw == "" and allow_blank:
                return ""

        if validator is None:
            return raw

        ok, msg_or_val = validator(raw)
        if ok:
            return msg_or_val
        print("[INVALID] " + msg_or_val)


def validate_major(v):
    if not re.match(r"^\d+$", v):
        return False, "Enter numbers only (13..18)."
    n = int(v)
    if n < MIN_VER or n > MAX_VER:
        return False, f"Version must be between {MIN_VER} and {MAX_VER}."
    return True, n


def validate_port(v):
    if not re.match(r"^\d+$", v):
        return False, "Port must be a number (1..65535)."
    n = int(v)
    if n < 1 or n > 65535:
        return False, "Port must be between 1 and 65535."
    return True, n


def validate_abspath(v):
    if not v.startswith("/"):
        return False, "Enter an absolute path (must start with /)."
    return True, v


def detect_arch():
    out = run(["uname", "-m"], capture=True).strip()
    if out in ("x86_64", "aarch64", "ppc64le"):
        return out
    return "x86_64"


def write_file(path, content, mode=0o644):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def ensure_dir(path, owner=None, mode=None):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
    if mode is not None:
        os.chmod(path, mode)
    if owner is not None:
        run(["chown", owner, path], check=True)


def read_first_match(path, pattern, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.search(pattern, line)
                if m:
                    return m.group(1).strip()
    except Exception:
        return default
    return default


# --- System Info Helpers for Report ---

def get_os_pretty_name():
    return read_first_match("/etc/os-release", r'^PRETTY_NAME="?([^"\n]+)"?', default="unknown")


def get_cpu_info():
    # Attempt to get model name
    model = read_first_match("/proc/cpuinfo", r"^model name\s*:\s*(.+)$", default="unknown")
    # Count cores
    cores = os.cpu_count() or 0
    return model, cores


def get_mem_total_mb():
    kb = read_first_match("/proc/meminfo", r"^MemTotal:\s*(\d+)\s*kB", default="0")
    try:
        kb_i = int(kb)
    except Exception:
        kb_i = 0
    return kb_i // 1024


def get_loadavg():
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def get_disk_usage_str(path):
    try:
        du = shutil.disk_usage(path)
        gb = 1024**3
        return f"Total: {du.total//gb} GB | Used: {du.used//gb} GB | Free: {du.free//gb} GB"
    except Exception:
        return "unknown"


# --- Installation Helpers ---

def set_selinux_context_for_pgdata(pgdata):
    if not shutil.which("getenforce"):
        return
    st = run(["getenforce"], capture=True, check=False)
    st = (st or "").strip().lower()
    if st not in ("enforcing", "permissive"):
        return

    if pgdata.startswith("/var/lib/pgsql"):
        return

    if not shutil.which("semanage"):
        run(["dnf", "-y", "install", "policycoreutils-python-utils"], check=True)

    pattern = pgdata.rstrip("/") + "(/.*)?"
    p = subprocess.run(["semanage", "fcontext", "-a", "-t", "postgresql_db_t", pattern])
    if p.returncode != 0:
        print("[WARN] semanage fcontext add failed (maybe already exists). Continuing...")

    run(["restorecon", "-Rv", pgdata], check=False)


def append_if_missing(path, marker, line_to_add):
    existing = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            existing = f.read()
    if marker in existing:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n" + line_to_add + "\n")


def get_postgres_home_user_dir():
    # Typically /var/lib/pgsql or /home/postgres depending on config
    p = subprocess.run(
        ["getent", "passwd", "postgres"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    if p.returncode != 0:
        return "/var/lib/pgsql"
    parts = p.stdout.strip().split(":")
    if len(parts) >= 6 and parts[5]:
        return parts[5]
    return "/var/lib/pgsql"


def rpm_detect_pghome(major):
    cand_pkgs = [f"postgresql{major}-server", f"postgresql{major}"]
    wanted = ("/bin/initdb", "/bin/pg_ctl", "/bin/psql")
    for pkg in cand_pkgs:
        p = subprocess.run(
            ["rpm", "-ql", pkg],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if p.returncode != 0:
            continue
        lines = p.stdout.splitlines()
        for w in wanted:
            for path in lines:
                if path.endswith(w):
                    bin_dir = os.path.dirname(path)
                    return os.path.dirname(bin_dir)
    return None


def binaries_ok(pghome):
    if not pghome:
        return False
    need = [
        os.path.join(pghome, "bin", "initdb"),
        os.path.join(pghome, "bin", "pg_ctl"),
        os.path.join(pghome, "bin", "psql"),
    ]
    return all(os.path.exists(f) for f in need)


def install_pgdg_repo(arch):
    run(["dnf", "-y", "install", "dnf-plugins-core", "ca-certificates", "curl"], check=True)

    subprocess.run(["dnf", "config-manager", "--set-enabled", "powertools"])
    subprocess.run(["dnf", "config-manager", "--enable", "powertools"])

    run(["dnf", "-y", "install",
         "https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm"], check=True)

    pgdg_repo_url = (
        f"https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-{arch}/"
        f"pgdg-redhat-repo-latest.noarch.rpm"
    )
    run(["dnf", "-y", "install", pgdg_repo_url], check=True)
    run(["dnf", "-qy", "module", "disable", "postgresql"], check=True)


def ensure_packages_present(major):
    pkgs = [
        f"postgresql{major}-server",
        f"postgresql{major}",
        f"postgresql{major}-contrib",
    ]
    run(["dnf", "-y", "install"] + pkgs, check=True)
    return pkgs


def force_reinstall_flow(pkgs):
    print("\n[INFO] Binaries not found. Trying: dnf reinstall ...")
    run(["dnf", "-y", "reinstall"] + pkgs, check=False)
    for p in pkgs:
        print(f"\n[INFO] rpm -V {p} (verification)")
        run(["rpm", "-V", p], check=False)


def remove_install_flow(pkgs):
    print("\n[INFO] Reinstall didn't help. Trying: remove -> clean -> install ...")
    run(["dnf", "-y", "remove"] + pkgs, check=False)
    run(["dnf", "-y", "clean", "all"], check=False)
    run(["dnf", "-y", "makecache"], check=False)
    run(["dnf", "-y", "install"] + pkgs, check=True)


def replace_or_append_conf(conf_path, kv_lines, file_mode=0o600):
    if not os.path.isfile(conf_path):
        die(f"postgresql.conf not found: {conf_path}")

    with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    regex_map = {k: re.compile(rf"^\s*#?\s*{re.escape(k)}\s*=") for k, _ in kv_lines}
    seen = {k: False for k, _ in kv_lines}

    out = []
    for line in lines:
        replaced = False
        for k, v in kv_lines:
            if regex_map[k].match(line):
                out.append(f"{k} = {v}\n")
                seen[k] = True
                replaced = True
                break
        if not replaced:
            out.append(line)

    if any(not ok for ok in seen.values()):
        out.append("\n# --- Set by installer script ---\n")
        for k, v in kv_lines:
            if not seen[k]:
                out.append(f"{k} = {v}\n")

    write_file(conf_path, "".join(out), mode=file_mode)
    run(["chown", "postgres:postgres", conf_path], check=True)


def configure_postgresql(pgdata, port):
    conf = os.path.join(pgdata, "postgresql.conf")

    pg_log_dir = os.path.join(pgdata, "log")
    ensure_dir(pg_log_dir, owner="postgres:postgres", mode=0o700)

    settings = [
        ("port", str(port)),

        ("logging_collector", "on"),
        ("log_directory", "'log'"),

        # Requested logging settings (as-is)
        ("log_min_messages", "'error'"),
        ("log_statement", "'ddl'"),
        ("log_filename", "'postgresql-%Y-%m-%d.log'"),
        ("log_min_duration_statement", "'1000'"),
        ("log_lock_waits", "'on'"),
        ("log_checkpoints", "'on'"),
        ("log_autovacuum_min_duration", "'0'"),
    ]
    replace_or_append_conf(conf, settings, file_mode=0o600)


def write_env_profile(real_pghome, pgdata, port):
    env_sh = "/etc/profile.d/pgsql.sh"
    env_content = (
        "# PostgreSQL env (generated)\n"
        f"export PGHOME=\"{real_pghome}\"\n"
        f"export PGDATA=\"{pgdata}\"\n"
        f"export PGPORT=\"{port}\"\n"
        "export PATH=\"$PGHOME/bin:$PATH\"\n"
    )
    write_file(env_sh, env_content, mode=0o644)


def fmt_kv_block(pairs, key_width=18):
    lines = []
    for k, v in pairs:
        lines.append(f"{k:<{key_width}} : {v}")
    return lines


# ==========================================
# REPORT GENERATION
# ==========================================
def generate_final_report(major, pgdata, real_pghome, port, arch):
    # Gather System Info
    os_name = get_os_pretty_name()
    cpu_model, cpu_cores = get_cpu_info()
    mem_mb = get_mem_total_mb()
    loadavg = get_loadavg()
    pg_disk = get_disk_usage_str(pgdata)

    # Gather Verification Info
    psql_bin = os.path.join(real_pghome, "bin", "psql")
    psql_ver = run(["runuser", "-u", "postgres", "--", psql_bin, "--version"], capture=True, check=False) or "Unknown"
    db_ver = run(
        ["runuser", "-u", "postgres", "--", psql_bin, "-p", str(port), "-c", "select version();"],
        capture=True, check=False
    ) or "Connection Failed"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_filename = f"install_report_pg{major}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    report_path = os.path.join(REPORT_BASE_DIR, report_filename)

    ensure_dir(REPORT_BASE_DIR, owner="postgres:postgres", mode=0o755)

    # Build Content
    lines = []
    lines.append("#" * SEP_WIDTH)
    lines.append(f"{'POSTGRESQL INSTALLATION REPORT':^{SEP_WIDTH}}")
    lines.append("#" * SEP_WIDTH)
    lines.append("")

    lines.append("-" * SEP_WIDTH)
    lines.append(" 1. SYSTEM INFORMATION")
    lines.append("-" * SEP_WIDTH)
    lines.extend(fmt_kv_block([
        ("Timestamp", now_str),
        ("OS", os_name),
        ("Architecture", arch),
        ("CPU Model", cpu_model),
        ("CPU Cores", str(cpu_cores)),
        ("Total Memory", f"{mem_mb} MB"),
        ("Load Average", loadavg),
    ]))
    lines.append("")

    lines.append("-" * SEP_WIDTH)
    lines.append(" 2. POSTGRESQL CONFIGURATION")
    lines.append("-" * SEP_WIDTH)
    lines.extend(fmt_kv_block([
        ("Major Version", str(major)),
        ("Binary Path (PGHOME)", real_pghome),
        ("Data Path (PGDATA)", pgdata),
        ("Port", str(port)),
        ("Disk Usage (PGDATA)", pg_disk),
        ("Log Directory", os.path.join(pgdata, 'log')),
    ]))
    lines.append("")

    lines.append("-" * SEP_WIDTH)
    lines.append(" 3. VERIFICATION")
    lines.append("-" * SEP_WIDTH)
    lines.append(f"Client Version: {psql_ver.strip()}")
    lines.append("Server Version Query:")
    lines.append(db_ver.strip())
    lines.append("")
    
    lines.append("#" * SEP_WIDTH)
    lines.append("END OF REPORT")
    lines.append("#" * SEP_WIDTH)
    lines.append("")

    # Write to file
    content = "\n".join(lines)
    write_file(report_path, content, mode=0o644)
    run(["chown", "postgres:postgres", report_path], check=True)

    return report_path


def main():
    if not is_root():
        die(f"Run as root: sudo python3 {os.path.basename(sys.argv[0])}")

    print_block(
        "PostgreSQL (PGDG) installation for Rocky Linux 8",
        [
            "Select major version 13..18.",
            "PGDATA and Port can be customized.",
            "Final report will be saved to /home/postgres/installer_log/"
        ],
        char="#"
    )

    major = prompt("PostgreSQL major version (13..18)", default=17, validator=validate_major)

    default_pgdata = f"/var/lib/pgsql/{major}/data"
    pgdata = prompt("PGDATA (data directory)", default=default_pgdata, validator=validate_abspath)
    pgdata = os.path.normpath(pgdata)

    # Removed PGHOME prompt. Auto-detection will be used.

    port = prompt("PostgreSQL port", default=5432, validator=validate_port)

    arch = detect_arch()
    install_pgdg_repo(arch)
    pkgs = ensure_packages_present(major)

    real_pghome = rpm_detect_pghome(major)

    if not binaries_ok(real_pghome):
        force_reinstall_flow(pkgs)
        real_pghome = rpm_detect_pghome(major)

    if not binaries_ok(real_pghome):
        remove_install_flow(pkgs)
        real_pghome = rpm_detect_pghome(major)

    if not binaries_ok(real_pghome):
        print_block("DEBUG", [
            f"rpm -ql postgresql{major}-server | head -n 30",
            f"ls -la /usr/pgsql-{major} /usr/pgsql-{major}/bin",
            "mount | grep ' /usr '",
        ], char="#")
        die("Binaries not found. Installation failed.")

    initdb_bin = os.path.join(real_pghome, "bin", "initdb")
    pg_ctl_bin = os.path.join(real_pghome, "bin", "pg_ctl")

    ensure_dir(pgdata, owner="postgres:postgres", mode=0o700)
    set_selinux_context_for_pgdata(pgdata)

    if os.path.exists(os.path.join(pgdata, "PG_VERSION")):
        print("[INFO] PGDATA already initialized. initdb skipped.")
    else:
        run(["runuser", "-u", "postgres", "--", initdb_bin, "-D", pgdata], check=True)

    configure_postgresql(pgdata, port)

    # Start/Restart logic (Removed -l logfile)
    st = subprocess.run(["runuser", "-u", "postgres", "--", pg_ctl_bin, "-D", pgdata, "status"]).returncode
    if st == 0:
        print("[INFO] PostgreSQL running. Restarting...")
        run(["runuser", "-u", "postgres", "--", pg_ctl_bin, "-D", pgdata, "restart"], check=True)
    else:
        print("[INFO] Starting PostgreSQL...")
        run(["runuser", "-u", "postgres", "--", pg_ctl_bin, "-D", pgdata, "start"], check=True)

    write_env_profile(real_pghome, pgdata, port)

    pg_home_user = get_postgres_home_user_dir()
    for fname in (".bash_profile", ".bashrc"):
        fpath = os.path.join(pg_home_user, fname)
        append_if_missing(fpath, "source /etc/profile.d/pgsql.sh", "source /etc/profile.d/pgsql.sh")
        subprocess.run(["chown", "postgres:postgres", fpath])

    # Generate Report
    report_file = generate_final_report(major, pgdata, real_pghome, port, arch)

    print_block(
        "INSTALLATION COMPLETE",
        [
            f"Report saved to : {report_file}",
            f"PostgreSQL Log  : {os.path.join(pgdata, 'log')}",
            "",
            "Commands for postgres user:",
            "  su - postgres",
            "  psql -p $PGPORT -c \"select 1;\"",
            "  pg_ctl -D $PGDATA status",
        ],
        char="#"
    )


if __name__ == "__main__":
    main()


```
