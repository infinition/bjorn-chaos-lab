"""
Bjorn Chaos Lab -- Core Engine
Manages Docker victim containers via SSH on a remote Docker host.
Supports multiple difficulty levels, diverse vulnerability scenarios,
flag validation, and credential export.
"""

import paramiko
import random
import string
import shlex
import time
import json
import os
import re
import threading
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable

logger = logging.getLogger("lab_engine")

# =============================================================================
# DATA POOLS
# =============================================================================

EXTENSIONS = [".txt", ".pdf", ".sql", ".conf", ".bak", ".log", ".key", ".pem"]
FILENAMES = [
    "flag", "password_hint", "note", "private_key", "internal_info",
    "backup", "credentials", "secret", "todo", "config_dump",
]
DIRECTORIES = ["/home/{user}", "/var/tmp", "/var/www/html", "/opt", "/usr/local/share"]

COMMON_USERNAMES = [
    "admin", "guest", "user", "dev", "test", "manager", "boss", "intern",
    "operator", "sysadmin", "webmaster", "deploy", "backup_user",
]
WEAK_PASSWORDS = [
    "123456", "password", "12345", "admin", "12345678", "letmein",
    "qwerty", "welcome1", "p@ssw0rd", "iloveyou",
]

SYSTEM_USERS = frozenset([
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "systemd-network", "systemd-resolve", "messagebus",
    "systemd-timesync", "syslog", "_apt", "tss", "uuidd", "tcpdump",
    "sshd", "mysql", "operator",
])

# Scenarios available per difficulty
DIFFICULTY_SCENARIOS = {
    "easy": ["web", "db", "files", "ftp"],
    "medium": ["web", "db", "files", "ftp", "sqli", "lfi", "privesc_suid",
               "git_exposure", "path_traversal"],
    "hard": ["web", "db", "files", "ftp", "sqli", "lfi", "cmdi", "upload",
             "ssrf", "path_traversal", "git_exposure",
             "privesc_suid", "privesc_sudo", "privesc_cron", "privesc_path",
             "ssh_key_leak"],
}

# Password complexity per difficulty
DIFFICULTY_PASSWORDS = {
    "easy": "low",
    "medium": "medium",
    "hard": "high",
}


# =============================================================================
# LAB ENGINE
# =============================================================================

class LabEngine:
    """
    Core engine for managing Bjorn Chaos Lab victim containers.
    Thread-safe for use from the web server.
    """

    def __init__(self, docker_host: str, ssh_user: str, ssh_pass: str,
                 network: str = "macvlan_zombieland",
                 event_callback: Optional[Callable[[str, str], None]] = None):
        self.docker_host = docker_host
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        self.network = network
        self.docker_binary = "docker"
        self.targets: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        self._client: Optional[paramiko.SSHClient] = None
        self._connected = False
        self._event_cb = event_callback

    # -------------------------------------------------------------------------
    # Events
    # -------------------------------------------------------------------------

    def _emit(self, level: str, message: str):
        logger.info(f"[{level.upper()}] {message}")
        if self._event_cb:
            try:
                self._event_cb(level, message)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # SSH Connection
    # -------------------------------------------------------------------------

    def connect(self) -> bool:
        with self._lock:
            return self._do_connect()

    def _do_connect(self) -> bool:
        try:
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass

            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._client.connect(
                self.docker_host,
                username=self.ssh_user,
                password=self.ssh_pass,
                timeout=10,
                banner_timeout=10,
            )
            self._connected = True
            self._emit("success", f"Connected to Docker host: {self.docker_host}")
            self._detect_docker_binary()
            return True

        except Exception as e:
            self._connected = False
            self._emit("error", f"SSH connection error: {e}")
            return False

    def disconnect(self):
        with self._lock:
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
            self._connected = False

    @property
    def is_connected(self) -> bool:
        if not self._connected or not self._client:
            return False
        try:
            transport = self._client.get_transport()
            return transport is not None and transport.is_active()
        except Exception:
            self._connected = False
            return False

    def _ensure_connected(self):
        if not self.is_connected:
            self._emit("warn", "Connection lost, attempting reconnect...")
            if not self._do_connect():
                raise ConnectionError("Cannot reconnect to Docker host")

    # -------------------------------------------------------------------------
    # Command Execution
    # -------------------------------------------------------------------------

    def _detect_docker_binary(self):
        for candidate in ["/usr/local/bin/docker", "/usr/bin/docker", "docker"]:
            _, _, code = self._exec(f"{candidate} --version", silent=True)
            if code == 0:
                self.docker_binary = candidate
                self._emit("info", f"Docker found: {candidate}")
                return
        self._emit("warn", "Docker binary not found, using 'docker' as default")
        self.docker_binary = "docker"

    def _exec(self, cmd: str, use_sudo: bool = False, silent: bool = False,
              timeout: int = 30) -> tuple:
        self._ensure_connected()

        full_cmd = f"sudo -S {cmd}" if use_sudo else cmd

        try:
            stdin, stdout, stderr = self._client.exec_command(full_cmd, timeout=timeout)

            if use_sudo:
                stdin.write(self.ssh_pass + "\n")
                stdin.flush()

            exit_status = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()

            if use_sudo and err:
                err_lines = [l for l in err.splitlines()
                             if not l.startswith("[sudo]") and "password" not in l.lower()]
                err = "\n".join(err_lines).strip()

            if exit_status != 0 and not silent:
                self._emit("warn", f"Command failed ({exit_status}): {cmd}")
                if err:
                    self._emit("warn", f"  stderr: {err[:200]}")

            return out, err, exit_status

        except Exception as e:
            if not silent:
                self._emit("error", f"Execution error: {e}")
            return "", str(e), -1

    def _docker(self, cmd: str, silent: bool = False, timeout: int = 60) -> tuple:
        return self._exec(f"{self.docker_binary} {cmd}", use_sudo=True,
                          silent=silent, timeout=timeout)

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _generate_password(complexity: str = "medium") -> str:
        if complexity == "low":
            return random.choice(WEAK_PASSWORDS)
        elif complexity == "high":
            chars = string.ascii_letters + string.digits + "!@#$%&"
            return "".join(random.choices(chars, k=16))
        else:
            return "".join(random.choices(string.ascii_letters + string.digits, k=10))

    @staticmethod
    def _create_flag() -> str:
        suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=24))
        return f"BJORN_CTF_{suffix}"

    @staticmethod
    def _sanitize_username(name: str) -> str:
        if name.lower() in SYSTEM_USERS:
            return f"usr_{name}"
        return name

    def _get_container_ip(self, container_name: str) -> str:
        out, _, code = self._docker(
            f"inspect -f '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {shlex.quote(container_name)}",
            silent=True
        )
        if code == 0 and out:
            ip = out.strip().strip("'\"")
            if ip:
                return ip
        return "N/A"

    # -------------------------------------------------------------------------
    # Docker Image Check
    # -------------------------------------------------------------------------

    def check_image_exists(self) -> bool:
        out, _, code = self._docker("images -q bjorn-victim", silent=True)
        return code == 0 and bool(out.strip())

    # -------------------------------------------------------------------------
    # Deploy
    # -------------------------------------------------------------------------

    def deploy_targets(self, count: int = 1, mode: str = "random",
                       difficulty: str = "medium") -> List[Dict]:
        results = []
        for i in range(count):
            try:
                intel = self._deploy_single(suffix=str(i), mode=mode, difficulty=difficulty)
                if intel:
                    results.append(intel)
            except Exception as e:
                self._emit("error", f"Deploy error for target {i}: {e}")
        return results

    def _deploy_single(self, suffix: str, mode: str = "random",
                       difficulty: str = "medium") -> Optional[Dict]:
        srv_name = f"target-{suffix}-{random.randint(100, 999)}"
        sys_user = self._sanitize_username(random.choice(COMMON_USERNAMES))
        pass_complexity = DIFFICULTY_PASSWORDS.get(difficulty, "medium")
        sys_pass = self._generate_password(pass_complexity)

        self._emit("info", f"Deploying {srv_name} (difficulty: {difficulty})...")

        # Resource limits based on difficulty
        mem_limit = {"easy": "256m", "medium": "384m", "hard": "512m"}.get(difficulty, "384m")

        run_cmd = (
            f"run -d --name {shlex.quote(srv_name)} "
            f"--hostname {shlex.quote(srv_name)} "
            f"--net {shlex.quote(self.network)} "
            f"--memory {mem_limit} --cpus 0.5 "
            f"--restart unless-stopped "
            f"bjorn-victim"
        )
        out, err, code = self._docker(run_cmd, timeout=120)

        if code != 0:
            self._emit("error", f"Failed to launch {srv_name}: {err}")
            return None

        self._emit("success", f"Container {srv_name} launched. ID: {out[:12]}")

        try:
            ip = self._get_container_ip(srv_name)
        except Exception:
            ip = "N/A"

        initial_intel = {
            "hostname": srv_name,
            "ip": ip,
            "status": "starting",
            "mode": mode,
            "difficulty": difficulty,
            "deployed_at": datetime.now().isoformat(),
            "system": {"user": sys_user, "password": sys_pass},
            "root_password": "",
            "services": [],
            "flags": [],
        }
        with self._lock:
            self.targets[srv_name] = initial_intel

        # Wait for MySQL
        self._emit("info", "Waiting for MySQL to start...")
        mysql_ready = False
        for attempt in range(20):
            _, _, code = self._docker(
                f"exec {shlex.quote(srv_name)} test -f /var/run/mysql-ready",
                silent=True, timeout=10
            )
            if code == 0:
                mysql_ready = True
                self._emit("success", "MySQL is ready.")
                break
            time.sleep(3)

        if not mysql_ready:
            self._emit("warn", "MySQL TIMEOUT -- continuing without MySQL.")

        ip = self._get_container_ip(srv_name)
        self._emit("info", f"Container IP: {ip}")

        # Create system user
        q_name = shlex.quote(srv_name)
        self._docker(f"exec {q_name} useradd -m -s /bin/bash {shlex.quote(sys_user)}", silent=True)
        chpasswd_cmd = shlex.quote(f"echo {sys_user}:{sys_pass} | chpasswd")
        self._docker(f"exec {q_name} bash -c {chpasswd_cmd}")

        # Set root password
        root_complexity = {"easy": "medium", "medium": "high", "hard": "high"}.get(difficulty, "high")
        root_pass = self._generate_password(root_complexity)
        root_chpasswd = shlex.quote(f"echo root:{root_pass} | chpasswd")
        self._docker(f"exec {q_name} bash -c {root_chpasswd}")

        intel = {
            "hostname": srv_name,
            "ip": ip,
            "status": "running",
            "mode": mode,
            "difficulty": difficulty,
            "deployed_at": datetime.now().isoformat(),
            "system": {"user": sys_user, "password": sys_pass},
            "root_password": root_pass,
            "services": [
                {"type": "ssh", "port": 22, "creds": f"{sys_user}:{sys_pass}"},
                {"type": "ssh-root", "port": 22, "creds": f"root:{root_pass}"},
                {"type": "telnet", "port": 23, "creds": f"{sys_user}:{sys_pass}"},
            ],
            "flags": [],
        }

        # Select scenarios
        available = DIFFICULTY_SCENARIOS.get(difficulty, DIFFICULTY_SCENARIOS["medium"])

        if mode == "random":
            count = random.randint(2, min(5, len(available)))
            chosen = random.sample(available, count)
            self._emit("info", f"Random mode: selected scenarios: {', '.join(chosen)}")
        elif mode == "web":
            chosen = [s for s in ["web", "sqli", "lfi", "cmdi", "upload", "ssrf", "path_traversal", "git_exposure"] if s in available]
        elif mode == "database":
            chosen = ["db"] if "db" in available else []
        elif mode == "network":
            chosen = [s for s in ["files", "ftp"] if s in available]
        elif mode == "full":
            chosen = list(available)
        else:
            chosen = [mode] if mode in available else ["web"]

        # Execute selected scenarios
        if "web" in chosen:
            intel = self._setup_web(srv_name, suffix, intel)
        if "sqli" in chosen and mysql_ready:
            intel = self._setup_sqli(srv_name, intel, difficulty)
        if "lfi" in chosen:
            intel = self._setup_lfi(srv_name, intel)
        if "cmdi" in chosen:
            intel = self._setup_cmdi(srv_name, intel)
        if "upload" in chosen:
            intel = self._setup_upload(srv_name, intel)
        if "db" in chosen and mysql_ready:
            intel = self._setup_database(srv_name, intel)
        if "files" in chosen:
            intel = self._setup_files(srv_name, sys_user, intel)
        if "ftp" in chosen:
            intel = self._setup_ftp(srv_name, sys_user, sys_pass, intel)
        if "ssrf" in chosen:
            intel = self._setup_ssrf(srv_name, intel)
        if "path_traversal" in chosen:
            intel = self._setup_path_traversal(srv_name, intel)
        if "git_exposure" in chosen:
            intel = self._setup_git_exposure(srv_name, intel)
        if "privesc_suid" in chosen:
            intel = self._setup_privesc_suid(srv_name, sys_user, intel)
        if "privesc_sudo" in chosen:
            intel = self._setup_privesc_sudo(srv_name, sys_user, intel)
        if "privesc_cron" in chosen:
            intel = self._setup_privesc_cron(srv_name, sys_user, intel)
        if "privesc_path" in chosen:
            intel = self._setup_privesc_path(srv_name, sys_user, intel)
        if "ssh_key_leak" in chosen:
            intel = self._setup_ssh_key_leak(srv_name, sys_user, intel)

        with self._lock:
            intel["status"] = "running"
            self.targets[srv_name] = intel

        self._emit("success", f"{srv_name} fully configured ({ip}).")
        return intel

    # -------------------------------------------------------------------------
    # Scenario Builders -- Original
    # -------------------------------------------------------------------------

    def _setup_web(self, srv_name: str, suffix: str, intel: Dict) -> Dict:
        self._emit("info", f"[{srv_name}] Setting up web (admin panel + robots.txt)...")

        web_flag = self._create_flag()
        admin_user = "admin"
        admin_pass = self._generate_password("low")
        q_name = shlex.quote(srv_name)

        robots = f"User-agent: *\nDisallow: /admin_panel_{suffix}.php\n# Flag: {web_flag}"
        robots_cmd = shlex.quote(f"printf '%s' '{robots}' > /var/www/html/robots.txt")
        self._docker(f"exec {q_name} bash -c {robots_cmd}")

        php_content = f"""<?php
$valid_user = "{admin_user}";
$valid_pass = "{admin_pass}";
if (isset($_POST["user"]) && isset($_POST["pass"])) {{
  if ($_POST["user"] == $valid_user && $_POST["pass"] == $valid_pass) {{
    echo "<h1>Welcome Admin!</h1><p>Secret dashboard access granted.</p>";
  }} else {{ echo "Access Denied"; }}
}}
?>
<form method="POST">User: <input name="user"><br>Pass: <input type="password" name="pass"><br><input type="submit" value="Login"></form>"""
        php_file = f"/var/www/html/admin_panel_{suffix}.php"
        write_cmd = f"cat > {php_file} << 'BJORN_EOF'\n{php_content}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")

        intel["services"].append({
            "type": "http", "port": 80,
            "details": f"Admin Panel at /admin_panel_{suffix}.php",
            "creds": f"{admin_user}:{admin_pass}",
        })
        intel["flags"].append({"location": "web_robots.txt", "value": web_flag})
        self._emit("success", f"[{srv_name}] Web configured.")
        return intel

    def _setup_database(self, srv_name: str, intel: Dict) -> Dict:
        self._emit("info", f"[{srv_name}] Setting up MySQL (corp_data database)...")

        db_name = "corp_data"
        sql_lines = [
            f"CREATE DATABASE IF NOT EXISTS {db_name};",
            f"USE {db_name};",
            "CREATE TABLE IF NOT EXISTS employees (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(50), email VARCHAR(100), pass_hash VARCHAR(100));",
        ]

        for _ in range(10):
            u = "".join(random.choices(string.ascii_lowercase, k=5))
            sql_lines.append(
                f"INSERT INTO employees (name, email, pass_hash) VALUES ('{u}', '{u}@corp.local', MD5('{random.randint(1000, 9999)}'));"
            )

        sql_flag = self._create_flag()
        sql_lines.append(
            f"INSERT INTO employees (name, email, pass_hash) VALUES ('Admin', 'admin@corp.local', '{sql_flag}');"
        )

        sql_script = " ".join(sql_lines)
        self._docker(
            f"exec {shlex.quote(srv_name)} mysql -e {shlex.quote(sql_script)}",
            timeout=30
        )

        db_user = "db_audit"
        db_pass = self._generate_password("medium")
        grant_sql = f"CREATE USER IF NOT EXISTS '{db_user}'@'%' IDENTIFIED BY '{db_pass}'; GRANT SELECT ON {db_name}.* TO '{db_user}'@'%'; FLUSH PRIVILEGES;"
        self._docker(
            f"exec {shlex.quote(srv_name)} mysql -e {shlex.quote(grant_sql)}",
            timeout=15
        )

        intel["services"].append({
            "type": "mysql", "port": 3306,
            "creds": f"{db_user}:{db_pass}",
            "database": db_name,
        })
        intel["flags"].append({"location": "mysql_database", "value": sql_flag})
        self._emit("success", f"[{srv_name}] MySQL configured.")
        return intel

    def _setup_files(self, srv_name: str, sys_user: str, intel: Dict) -> Dict:
        self._emit("info", f"[{srv_name}] Setting up SMB (public share)...")

        smb_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        self._docker(f"exec {q_name} mkdir -p /srv/smb/public")
        flag_cmd = shlex.quote(f"echo {smb_flag} > /srv/smb/public/flag.txt")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        hidden_flag = self._create_flag()
        fname = random.choice(FILENAMES) + random.choice(EXTENSIONS)
        hidden_cmd = shlex.quote(f"echo {hidden_flag} > /home/{sys_user}/.{fname}")
        self._docker(f"exec {q_name} bash -c {hidden_cmd}")

        smb_conf = "[Public]\n   path = /srv/smb/public\n   browseable = yes\n   read only = no\n   guest ok = yes"
        smb_cmd = shlex.quote(f"printf '%s' '{smb_conf}' >> /etc/samba/smb.conf")
        self._docker(f"exec {q_name} bash -c {smb_cmd}")
        self._docker(f"exec {q_name} service smbd restart", silent=True)

        intel["services"].append({
            "type": "smb", "port": 445,
            "details": "Public share at //hostname/Public (guest access)",
        })
        intel["flags"].append({"location": "smb_share (/srv/smb/public/flag.txt)", "value": smb_flag})
        intel["flags"].append({"location": f"hidden_file (/home/{sys_user}/.{fname})", "value": hidden_flag})
        self._emit("success", f"[{srv_name}] SMB configured.")
        return intel

    def _setup_ftp(self, srv_name: str, sys_user: str, sys_pass: str, intel: Dict) -> Dict:
        self._emit("info", f"[{srv_name}] Setting up FTP...")

        ftp_flag = self._create_flag()
        q_name = shlex.quote(srv_name)
        ftp_cmd = shlex.quote(f"echo {ftp_flag} > /home/{sys_user}/credentials.bak")
        self._docker(f"exec {q_name} bash -c {ftp_cmd}")

        intel["services"].append({
            "type": "ftp", "port": 21, "creds": f"{sys_user}:{sys_pass}",
        })
        intel["flags"].append({"location": f"ftp_file (/home/{sys_user}/credentials.bak)", "value": ftp_flag})
        self._emit("success", f"[{srv_name}] FTP configured.")
        return intel

    # -------------------------------------------------------------------------
    # Scenario Builders -- New Vulnerability Scenarios
    # -------------------------------------------------------------------------

    def _setup_sqli(self, srv_name: str, intel: Dict, difficulty: str) -> Dict:
        """SQL injection vulnerable login page."""
        self._emit("info", f"[{srv_name}] Setting up SQL injection challenge...")

        sqli_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Create a secret table with the flag
        sql = (
            "CREATE DATABASE IF NOT EXISTS webapp; USE webapp; "
            "CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50), password VARCHAR(100)); "
            "INSERT INTO users (username, password) VALUES ('admin', 'superSecretAdmin!'), ('guest', 'guest123'); "
            f"CREATE TABLE IF NOT EXISTS secrets (id INT AUTO_INCREMENT PRIMARY KEY, flag VARCHAR(100)); "
            f"INSERT INTO secrets (flag) VALUES ('{sqli_flag}');"
        )
        self._docker(f"exec {q_name} mysql -e {shlex.quote(sql)}", timeout=15)

        # Vulnerable PHP login page (uses string concatenation instead of prepared statements)
        php = """<?php
$conn = new mysqli("localhost", "root", "", "webapp");
if ($conn->connect_error) die("DB Error");
$msg = "";
if (isset($_POST["username"]) && isset($_POST["password"])) {
    $user = $_POST["username"];
    $pass = $_POST["password"];
    $sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = $conn->query($sql);
    if ($result && $result->num_rows > 0) {
        $msg = "<div style='color:#0f0'>Login successful! Welcome, " . htmlspecialchars($user) . ".</div>";
    } else {
        $msg = "<div style='color:#f00'>Invalid credentials.</div>";
    }
}
?>
<!DOCTYPE html>
<html><head><title>Corporate Login</title>
<style>body{background:#111;color:#eee;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1a1a2e;padding:2rem;border-radius:8px;border:1px solid #333;width:320px}
input{width:100%;padding:8px;margin:6px 0;background:#0d0d1a;color:#eee;border:1px solid #444;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:10px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:bold}
h2{color:#e94560;text-align:center}</style></head>
<body><div class="box"><h2>Corp Login Portal</h2>
<form method="POST"><input name="username" placeholder="Username">
<input name="password" type="password" placeholder="Password">
<button type="submit">Sign In</button></form>
<?php echo $msg; ?>
<p style="color:#555;font-size:11px;text-align:center;margin-top:12px">Hint: Try SQL injection on the login form. The flag is in the secrets table.</p>
</div></body></html>"""

        write_cmd = f"cat > /var/www/html/login.php << 'BJORN_EOF'\n{php}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")

        intel["services"].append({
            "type": "http", "port": 80,
            "details": "SQLi vulnerable login at /login.php",
            "creds": "admin:superSecretAdmin!",
        })
        intel["services"].append({
            "type": "http-guest", "port": 80,
            "details": "SQLi DB guest account",
            "creds": "guest:guest123",
        })
        intel["flags"].append({"location": "sqli_database (webapp.secrets)", "value": sqli_flag})
        self._emit("success", f"[{srv_name}] SQLi challenge configured.")
        return intel

    def _setup_lfi(self, srv_name: str, intel: Dict) -> Dict:
        """Local file inclusion vulnerable page."""
        self._emit("info", f"[{srv_name}] Setting up LFI challenge...")

        lfi_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Plant flag in a system file
        flag_cmd = shlex.quote(f"echo {lfi_flag} > /etc/bjorn_secret")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        # Vulnerable PHP page with file inclusion
        php = """<?php
$page = isset($_GET['page']) ? $_GET['page'] : 'home';
?>
<!DOCTYPE html>
<html><head><title>Corp Intranet</title>
<style>body{background:#111;color:#eee;font-family:monospace;margin:2rem}
a{color:#00ff41;margin-right:1rem}nav{margin-bottom:1rem;padding:1rem;border-bottom:1px solid #333}
.content{background:#1a1a2e;padding:1.5rem;border-radius:8px;border:1px solid #333}</style></head>
<body><h1 style="color:#00ff41">Corporate Intranet</h1>
<nav><a href="?page=home">Home</a><a href="?page=about">About</a><a href="?page=contact">Contact</a></nav>
<div class="content">
<?php
if ($page === 'home') {
    echo "<h2>Welcome</h2><p>Internal company portal. Use the navigation above.</p>";
    echo "<p style='color:#555;font-size:11px'>Hint: The page parameter loads files. Try including /etc/bjorn_secret</p>";
} elseif ($page === 'about') {
    echo "<h2>About Us</h2><p>A leading corporation in data management.</p>";
} elseif ($page === 'contact') {
    echo "<h2>Contact</h2><p>Email: admin@corp.local</p>";
} else {
    @include($page);
}
?>
</div></body></html>"""

        write_cmd = f"cat > /var/www/html/intranet.php << 'BJORN_EOF'\n{php}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")

        intel["services"].append({
            "type": "http", "port": 80,
            "details": "LFI vulnerable page at /intranet.php?page=",
        })
        intel["flags"].append({"location": "lfi_file (/etc/bjorn_secret)", "value": lfi_flag})
        self._emit("success", f"[{srv_name}] LFI challenge configured.")
        return intel

    def _setup_cmdi(self, srv_name: str, intel: Dict) -> Dict:
        """Command injection vulnerable page."""
        self._emit("info", f"[{srv_name}] Setting up command injection challenge...")

        cmdi_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Plant flag
        flag_cmd = shlex.quote(f"echo {cmdi_flag} > /opt/cmdi_flag.txt")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        php = """<?php
$output = "";
if (isset($_POST["target"])) {
    $target = $_POST["target"];
    $output = shell_exec("ping -c 2 " . $target . " 2>&1");
}
?>
<!DOCTYPE html>
<html><head><title>Network Diagnostics</title>
<style>body{background:#111;color:#eee;font-family:monospace;margin:2rem}
input{padding:8px;background:#0d0d1a;color:#eee;border:1px solid #444;border-radius:4px;width:300px}
button{padding:8px 16px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer}
pre{background:#0a0a1a;padding:1rem;border-radius:8px;border:1px solid #333;overflow-x:auto;max-height:400px}
.box{background:#1a1a2e;padding:2rem;border-radius:8px;border:1px solid #333;max-width:600px}</style></head>
<body><div class="box"><h2 style="color:#e94560">Network Ping Tool</h2>
<form method="POST"><input name="target" placeholder="Enter IP to ping" value="<?php echo isset($_POST['target'])?htmlspecialchars($_POST['target']):''; ?>">
<button type="submit">Ping</button></form>
<?php if ($output): ?><pre><?php echo htmlspecialchars($output); ?></pre><?php endif; ?>
<p style="color:#555;font-size:11px;margin-top:12px">Hint: Command injection via ; or | in the target field. Flag is at /opt/cmdi_flag.txt</p>
</div></body></html>"""

        write_cmd = f"cat > /var/www/html/ping.php << 'BJORN_EOF'\n{php}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")

        intel["services"].append({
            "type": "http", "port": 80,
            "details": "Command injection at /ping.php",
        })
        intel["flags"].append({"location": "cmdi_file (/opt/cmdi_flag.txt)", "value": cmdi_flag})
        self._emit("success", f"[{srv_name}] Command injection configured.")
        return intel

    def _setup_upload(self, srv_name: str, intel: Dict) -> Dict:
        """Unrestricted file upload vulnerability."""
        self._emit("info", f"[{srv_name}] Setting up file upload challenge...")

        upload_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Plant flag readable only via code execution
        flag_cmd = shlex.quote(f"echo {upload_flag} > /var/upload_flag.txt && chmod 644 /var/upload_flag.txt")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        # Create uploads directory
        self._docker(f"exec {q_name} bash -c {shlex.quote('mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads')}")

        php = """<?php
$msg = "";
if (isset($_FILES["file"])) {
    $target = "/var/www/html/uploads/" . basename($_FILES["file"]["name"]);
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target)) {
        $msg = "<div style='color:#0f0'>File uploaded: <a href='/uploads/" . htmlspecialchars(basename($_FILES["file"]["name"])) . "' style='color:#00ff41'>" . htmlspecialchars(basename($_FILES["file"]["name"])) . "</a></div>";
    } else {
        $msg = "<div style='color:#f00'>Upload failed.</div>";
    }
}
?>
<!DOCTYPE html>
<html><head><title>File Manager</title>
<style>body{background:#111;color:#eee;font-family:monospace;margin:2rem}
input[type=file]{color:#eee}button{padding:8px 16px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer}
.box{background:#1a1a2e;padding:2rem;border-radius:8px;border:1px solid #333;max-width:500px}</style></head>
<body><div class="box"><h2 style="color:#e94560">Employee File Upload</h2>
<form method="POST" enctype="multipart/form-data"><input type="file" name="file"><br><br>
<button type="submit">Upload</button></form>
<?php echo $msg; ?>
<p style="color:#555;font-size:11px;margin-top:12px">Hint: No file type restriction. Upload a PHP shell to read /var/upload_flag.txt</p>
</div></body></html>"""

        write_cmd = f"cat > /var/www/html/upload.php << 'BJORN_EOF'\n{php}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")

        intel["services"].append({
            "type": "http", "port": 80,
            "details": "Unrestricted file upload at /upload.php",
        })
        intel["flags"].append({"location": "upload_rce (/var/upload_flag.txt)", "value": upload_flag})
        self._emit("success", f"[{srv_name}] File upload challenge configured.")
        return intel

    # -------------------------------------------------------------------------
    # Privilege Escalation Scenarios
    # -------------------------------------------------------------------------

    def _setup_privesc_suid(self, srv_name: str, sys_user: str, intel: Dict) -> Dict:
        """SUID binary for privilege escalation (python3 with SUID)."""
        self._emit("info", f"[{srv_name}] Setting up SUID privilege escalation...")

        suid_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Place root-only flag
        flag_cmd = shlex.quote(f"echo {suid_flag} > /root/suid_flag.txt && chmod 600 /root/suid_flag.txt")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        # Set find as SUID (classic GTFOBins)
        self._docker(f"exec {q_name} chmod u+s /usr/bin/find")

        # Leave a hint
        hint_cmd = shlex.quote(f"echo 'Check for SUID binaries: find / -perm -4000 2>/dev/null' > /home/{sys_user}/README_PRIVESC.txt")
        self._docker(f"exec {q_name} bash -c {hint_cmd}")

        intel["flags"].append({"location": "privesc_suid (/root/suid_flag.txt via SUID find)", "value": suid_flag})
        self._emit("success", f"[{srv_name}] SUID privesc configured.")
        return intel

    def _setup_privesc_sudo(self, srv_name: str, sys_user: str, intel: Dict) -> Dict:
        """Misconfigured sudo for privilege escalation."""
        self._emit("info", f"[{srv_name}] Setting up sudo privilege escalation...")

        sudo_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Place root-only flag
        flag_cmd = shlex.quote(f"echo {sudo_flag} > /root/sudo_flag.txt && chmod 600 /root/sudo_flag.txt")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        # Allow user to run vim as root without password
        sudoers_cmd = shlex.quote(f"echo '{sys_user} ALL=(root) NOPASSWD: /usr/bin/vim' >> /etc/sudoers")
        self._docker(f"exec {q_name} bash -c {sudoers_cmd}")

        intel["flags"].append({"location": "privesc_sudo (/root/sudo_flag.txt via sudo vim)", "value": sudo_flag})
        self._emit("success", f"[{srv_name}] Sudo privesc configured.")
        return intel

    def _setup_privesc_cron(self, srv_name: str, sys_user: str, intel: Dict) -> Dict:
        """Writable cron job for privilege escalation."""
        self._emit("info", f"[{srv_name}] Setting up cron privilege escalation...")

        cron_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Place root-only flag
        flag_cmd = shlex.quote(f"echo {cron_flag} > /root/cron_flag.txt && chmod 600 /root/cron_flag.txt")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        # Create a world-writable script executed by root cron
        script_cmd = shlex.quote("echo '#!/bin/bash\necho Maintenance task running' > /opt/maintenance.sh && chmod 777 /opt/maintenance.sh")
        self._docker(f"exec {q_name} bash -c {script_cmd}")

        # Add cron job running as root every minute
        cron_cmd = shlex.quote("echo '* * * * * root /opt/maintenance.sh' >> /etc/crontab")
        self._docker(f"exec {q_name} bash -c {cron_cmd}")

        # Hint file
        hint_cmd = shlex.quote(f"echo 'Check /etc/crontab and /opt/maintenance.sh permissions' > /home/{sys_user}/CRON_HINT.txt")
        self._docker(f"exec {q_name} bash -c {hint_cmd}")

        intel["flags"].append({"location": "privesc_cron (/root/cron_flag.txt via writable /opt/maintenance.sh)", "value": cron_flag})
        self._emit("success", f"[{srv_name}] Cron privesc configured.")
        return intel

    # -------------------------------------------------------------------------
    # New Vulnerability Scenarios
    # -------------------------------------------------------------------------

    def _setup_ssrf(self, srv_name: str, intel: Dict) -> Dict:
        """Server-Side Request Forgery -- URL fetcher that can reach internal files."""
        self._emit("info", f"[{srv_name}] Setting up SSRF challenge...")

        ssrf_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Internal service with flag (listening on localhost:9999)
        internal_script = f"""#!/usr/bin/env python3
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.end_headers()
        self.wfile.write(b'INTERNAL ADMIN PANEL\\nFlag: {ssrf_flag}\\n')
    def log_message(self, *a): pass
socketserver.TCPServer(('127.0.0.1', 9999), H).serve_forever()
"""
        write_cmd = f"cat > /opt/internal_svc.py << 'BJORN_EOF'\n{internal_script}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")
        self._docker(f"exec {q_name} bash -c {shlex.quote('nohup python3 /opt/internal_svc.py &>/dev/null &')}")

        # Vulnerable PHP page that fetches URLs
        php = """<?php
$result = "";
if (isset($_POST["url"])) {
    $url = $_POST["url"];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $result = curl_exec($ch);
    if ($result === false) $result = "Error: " . curl_error($ch);
    curl_close($ch);
}
?>
<!DOCTYPE html>
<html><head><title>URL Preview Tool</title>
<style>body{background:#111;color:#eee;font-family:monospace;margin:2rem}
input{padding:8px;background:#0d0d1a;color:#eee;border:1px solid #444;border-radius:4px;width:400px}
button{padding:8px 16px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer}
pre{background:#0a0a1a;padding:1rem;border-radius:8px;border:1px solid #333;overflow-x:auto;max-height:400px;white-space:pre-wrap}
.box{background:#1a1a2e;padding:2rem;border-radius:8px;border:1px solid #333;max-width:650px}</style></head>
<body><div class="box"><h2 style="color:#e94560">URL Preview Service</h2>
<p>Enter a URL to fetch its content:</p>
<form method="POST"><input name="url" placeholder="https://example.com" value="<?php echo isset($_POST['url'])?htmlspecialchars($_POST['url']):''; ?>">
<button type="submit">Fetch</button></form>
<?php if ($result): ?><h3>Response:</h3><pre><?php echo htmlspecialchars($result); ?></pre><?php endif; ?>
<p style="color:#555;font-size:11px;margin-top:12px">Hint: This server has an internal service at http://127.0.0.1:9999</p>
</div></body></html>"""

        write_cmd = f"cat > /var/www/html/fetch.php << 'BJORN_EOF'\n{php}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")

        intel["services"].append({
            "type": "http", "port": 80,
            "details": "SSRF vulnerable URL fetcher at /fetch.php",
        })
        intel["flags"].append({"location": "ssrf_internal (http://127.0.0.1:9999 via /fetch.php)", "value": ssrf_flag})
        self._emit("success", f"[{srv_name}] SSRF challenge configured.")
        return intel

    def _setup_path_traversal(self, srv_name: str, intel: Dict) -> Dict:
        """Path traversal via file download endpoint."""
        self._emit("info", f"[{srv_name}] Setting up path traversal challenge...")

        traversal_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Plant flag
        flag_cmd = shlex.quote(f"echo {traversal_flag} > /etc/bjorn_traversal_flag")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        # Create some decoy files
        self._docker(f"exec {q_name} bash -c {shlex.quote('mkdir -p /var/www/html/documents')}")
        for fname in ["report_q1.txt", "report_q2.txt", "memo_internal.txt"]:
            self._docker(f"exec {q_name} bash -c {shlex.quote(f'echo Corporate document: {fname} > /var/www/html/documents/{fname}')}")

        php = """<?php
$file = isset($_GET['file']) ? $_GET['file'] : '';
if ($file) {
    $path = "/var/www/html/documents/" . $file;
    if (file_exists($path)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        readfile($path);
        exit;
    } else {
        $error = "File not found.";
    }
}
?>
<!DOCTYPE html>
<html><head><title>Document Portal</title>
<style>body{background:#111;color:#eee;font-family:monospace;margin:2rem}
a{color:#00ff41}.box{background:#1a1a2e;padding:2rem;border-radius:8px;border:1px solid #333;max-width:500px}
li{margin:6px 0}</style></head>
<body><div class="box"><h2 style="color:#e94560">Document Archive</h2>
<ul>
<li><a href="?file=report_q1.txt">Q1 Report</a></li>
<li><a href="?file=report_q2.txt">Q2 Report</a></li>
<li><a href="?file=memo_internal.txt">Internal Memo</a></li>
</ul>
<?php if (isset($error)): ?><p style="color:#f00"><?php echo $error; ?></p><?php endif; ?>
<p style="color:#555;font-size:11px;margin-top:12px">Hint: The file parameter is not sanitized. Try ../../etc/bjorn_traversal_flag</p>
</div></body></html>"""

        write_cmd = f"cat > /var/www/html/docs.php << 'BJORN_EOF'\n{php}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")

        intel["services"].append({
            "type": "http", "port": 80,
            "details": "Path traversal at /docs.php?file=",
        })
        intel["flags"].append({"location": "path_traversal (/etc/bjorn_traversal_flag via /docs.php)", "value": traversal_flag})
        self._emit("success", f"[{srv_name}] Path traversal challenge configured.")
        return intel

    def _setup_git_exposure(self, srv_name: str, intel: Dict) -> Dict:
        """Exposed .git directory with credentials in commit history."""
        self._emit("info", f"[{srv_name}] Setting up git exposure challenge...")

        git_flag = self._create_flag()
        git_pass = self._generate_password("medium")
        q_name = shlex.quote(srv_name)

        # Initialize a git repo in the web root with credentials in history
        git_cmds = f"""cd /var/www/html && \
git init && \
git config user.email 'dev@corp.local' && \
git config user.name 'Developer' && \
echo '<h1>Corp Website</h1>' > index.html && \
echo 'DB_USER=admin' > config.php && \
echo 'DB_PASS={git_pass}' >> config.php && \
echo 'SECRET_FLAG={git_flag}' >> config.php && \
git add -A && git commit -m 'initial commit with config' && \
echo '<?php echo \"Welcome to Corp\"; ?>' > config.php && \
git add -A && git commit -m 'removed sensitive config (oops)'"""

        self._docker(f"exec {q_name} bash -c {shlex.quote(git_cmds)}", timeout=30)

        intel["services"].append({
            "type": "http", "port": 80,
            "details": "Exposed .git directory (check /.git/)",
            "creds": f"admin:{git_pass}",
        })
        intel["flags"].append({"location": "git_history (/.git/ commit history)", "value": git_flag})
        self._emit("success", f"[{srv_name}] Git exposure challenge configured.")
        return intel

    def _setup_privesc_path(self, srv_name: str, sys_user: str, intel: Dict) -> Dict:
        """PATH hijacking privilege escalation."""
        self._emit("info", f"[{srv_name}] Setting up PATH hijacking privesc...")

        path_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Place root-only flag
        flag_cmd = shlex.quote(f"echo {path_flag} > /root/path_flag.txt && chmod 600 /root/path_flag.txt")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        # Create a SUID binary that calls 'service' without full path
        c_code = """#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("service --status-all");
    return 0;
}"""
        write_cmd = f"cat > /tmp/checker.c << 'BJORN_EOF'\n{c_code}\nBJORN_EOF"
        self._docker(f"exec {q_name} bash -c {shlex.quote(write_cmd)}")
        self._docker(f"exec {q_name} bash -c {shlex.quote('gcc -o /usr/local/bin/service-checker /tmp/checker.c && chmod u+s /usr/local/bin/service-checker && rm /tmp/checker.c')}")

        # Writable directory early in the user's PATH
        self._docker(f"exec {q_name} bash -c {shlex.quote(f'mkdir -p /home/{sys_user}/.local/bin && chown {sys_user}:{sys_user} /home/{sys_user}/.local/bin')}")
        profile_cmd = shlex.quote(f"echo 'export PATH=/home/{sys_user}/.local/bin:$PATH' >> /home/{sys_user}/.bashrc")
        self._docker(f"exec {q_name} bash -c {profile_cmd}")

        # Hint
        hint_cmd = shlex.quote(f"echo 'There is a SUID binary: /usr/local/bin/service-checker. It calls an external command without a full path.' > /home/{sys_user}/PATH_HINT.txt")
        self._docker(f"exec {q_name} bash -c {hint_cmd}")

        intel["flags"].append({"location": "privesc_path (/root/path_flag.txt via PATH hijack on service-checker)", "value": path_flag})
        self._emit("success", f"[{srv_name}] PATH hijacking privesc configured.")
        return intel

    def _setup_ssh_key_leak(self, srv_name: str, sys_user: str, intel: Dict) -> Dict:
        """SSH private key left in an accessible location."""
        self._emit("info", f"[{srv_name}] Setting up SSH key leak challenge...")

        key_flag = self._create_flag()
        q_name = shlex.quote(srv_name)

        # Place flag accessible only via root SSH
        flag_cmd = shlex.quote(f"echo {key_flag} > /root/ssh_key_flag.txt && chmod 600 /root/ssh_key_flag.txt")
        self._docker(f"exec {q_name} bash -c {flag_cmd}")

        # Generate an SSH keypair for root and leave the private key in a discoverable location
        key_cmds = f"""ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N '' -q && \
mkdir -p /root/.ssh && \
cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys && \
chmod 600 /root/.ssh/authorized_keys && \
cp /root/.ssh/id_rsa /var/www/html/.backup_key.pem && \
cp /root/.ssh/id_rsa /home/{sys_user}/.old_id_rsa"""
        self._docker(f"exec {q_name} bash -c {shlex.quote(key_cmds)}", timeout=30)

        intel["services"].append({
            "type": "http", "port": 80,
            "details": "Leaked SSH private key at /.backup_key.pem",
        })
        intel["flags"].append({"location": f"ssh_key_leak (/root/ssh_key_flag.txt via leaked key)", "value": key_flag})
        self._emit("success", f"[{srv_name}] SSH key leak challenge configured.")
        return intel

    # -------------------------------------------------------------------------
    # Flag Validation
    # -------------------------------------------------------------------------

    def validate_flag(self, flag_value: str) -> Optional[Dict]:
        """Check if a submitted flag matches any deployed flag.
        Returns the flag info dict if valid, None otherwise."""
        with self._lock:
            for hostname, target in self.targets.items():
                for flag in target.get("flags", []):
                    if flag["value"] == flag_value.strip():
                        return {
                            "valid": True,
                            "hostname": hostname,
                            "location": flag["location"],
                            "value": flag["value"],
                        }
        return None

    def get_all_flags(self) -> List[Dict]:
        """Return all flags across all targets."""
        flags = []
        with self._lock:
            for hostname, target in self.targets.items():
                for flag in target.get("flags", []):
                    flags.append({
                        "hostname": hostname,
                        "location": flag["location"],
                        "value": flag["value"],
                    })
        return flags

    # -------------------------------------------------------------------------
    # Credential Upload to Remote Bjorn Machine
    # -------------------------------------------------------------------------

    def upload_credentials(self, ssh_host: str, ssh_user: str, ssh_pass: str,
                           remote_path: str = "/home/bjorn/Bjorn/data/input/dictionary/") -> Dict:
        """Upload unique users and passwords to a remote machine via SSH.
        Reads existing files first to avoid duplicates. One entry per line."""
        self._emit("info", f"Connecting to {ssh_host} to upload credentials...")

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ssh_host, username=ssh_user, password=ssh_pass, timeout=10)
        except Exception as e:
            self._emit("error", f"Cannot connect to {ssh_host}: {e}")
            return {"success": False, "error": str(e)}

        try:
            # Collect current credentials from targets
            new_users = set()
            new_passwords = set()
            with self._lock:
                for target in self.targets.values():
                    sys = target.get("system", {})
                    if sys.get("user"):
                        new_users.add(sys["user"])
                    if sys.get("password"):
                        new_passwords.add(sys["password"])
                    if target.get("root_password"):
                        new_passwords.add(target["root_password"])
                    new_users.add("root")
                    for svc in target.get("services", []):
                        if svc.get("creds"):
                            parts = svc["creds"].split(":", 1)
                            if parts[0]:
                                new_users.add(parts[0])
                            if len(parts) > 1 and parts[1]:
                                new_passwords.add(parts[1])

            users_file = os.path.join(remote_path, "users.txt").replace("\\", "/")
            passwords_file = os.path.join(remote_path, "passwords.txt").replace("\\", "/")

            # Ensure remote directory exists
            client.exec_command(f"mkdir -p {shlex.quote(remote_path)}")
            time.sleep(0.5)

            # Read existing entries
            def read_remote_set(filepath):
                stdin, stdout, stderr = client.exec_command(f"cat {shlex.quote(filepath)} 2>/dev/null")
                content = stdout.read().decode("utf-8", errors="replace")
                return set(line.strip() for line in content.splitlines() if line.strip())

            existing_users = read_remote_set(users_file)
            existing_passwords = read_remote_set(passwords_file)

            # Compute new entries only
            users_to_add = new_users - existing_users
            passwords_to_add = new_passwords - existing_passwords

            # Append new entries
            added_users = 0
            added_passwords = 0

            if users_to_add:
                append_data = "\n".join(sorted(users_to_add)) + "\n"
                stdin, stdout, stderr = client.exec_command(
                    f"cat >> {shlex.quote(users_file)} << 'BJORN_EOF'\n{append_data}BJORN_EOF"
                )
                stdout.channel.recv_exit_status()
                added_users = len(users_to_add)

            if passwords_to_add:
                append_data = "\n".join(sorted(passwords_to_add)) + "\n"
                stdin, stdout, stderr = client.exec_command(
                    f"cat >> {shlex.quote(passwords_file)} << 'BJORN_EOF'\n{append_data}BJORN_EOF"
                )
                stdout.channel.recv_exit_status()
                added_passwords = len(passwords_to_add)

            total_users = len(existing_users) + added_users
            total_passwords = len(existing_passwords) + added_passwords

            result = {
                "success": True,
                "host": ssh_host,
                "users_added": added_users,
                "passwords_added": added_passwords,
                "total_users": total_users,
                "total_passwords": total_passwords,
            }

            self._emit("info", f"Collected {len(new_users)} users and {len(new_passwords)} passwords from {len(self.targets)} target(s)")
            if added_users > 0:
                self._emit("success", f"+{added_users} new user(s) appended to {users_file} (total: {total_users})")
            else:
                self._emit("info", f"No new users to add (already {total_users} in file)")
            if added_passwords > 0:
                self._emit("success", f"+{added_passwords} new password(s) appended to {passwords_file} (total: {total_passwords})")
            else:
                self._emit("info", f"No new passwords to add (already {total_passwords} in file)")
            self._emit("success", f"Credential upload to {ssh_host} complete: +{added_users} users, +{added_passwords} passwords")
            return result

        except Exception as e:
            self._emit("error", f"Credential upload failed: {e}")
            return {"success": False, "error": str(e)}
        finally:
            client.close()

    # -------------------------------------------------------------------------
    # List / Inspect / Delete
    # -------------------------------------------------------------------------

    def list_targets(self) -> List[Dict]:
        with self._lock:
            stored_targets = dict(self.targets)

        if stored_targets:
            result = []
            for name, intel in stored_targets.items():
                result.append({
                    "hostname": intel.get("hostname", name),
                    "container_id": intel.get("container_id", ""),
                    "ip": intel.get("ip", "N/A"),
                    "status": intel.get("status", "running"),
                    "mode": intel.get("mode", "unknown"),
                    "difficulty": intel.get("difficulty", "medium"),
                    "deployed_at": intel.get("deployed_at", ""),
                    "system": intel.get("system", {}),
                    "root_password": intel.get("root_password", ""),
                    "services": intel.get("services", []),
                    "flags": intel.get("flags", []),
                })
            return result

        # Fallback: discover via docker ps
        try:
            out, _, code = self._docker(
                "ps -a --filter name=target- --format '{{.Names}}|{{.Status}}|{{.ID}}'",
                silent=True
            )
        except Exception:
            return []
        if code != 0:
            return []

        live_targets = []
        for line in out.splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) < 3:
                continue

            name = parts[0].strip()
            status_str = parts[1].strip().lower()
            container_id = parts[2].strip()
            is_running = "up" in status_str

            try:
                ip = self._get_container_ip(name) if is_running else "N/A"
            except Exception:
                ip = "N/A"

            live_targets.append({
                "hostname": name,
                "container_id": container_id[:12],
                "ip": ip,
                "status": "running" if is_running else "stopped",
                "mode": "unknown",
                "difficulty": "unknown",
                "deployed_at": "",
                "system": {},
                "root_password": "",
                "services": [],
                "flags": [],
            })

        return live_targets

    def delete_target(self, hostname: str) -> bool:
        self._emit("info", f"Deleting {hostname}...")
        _, _, code = self._docker(f"rm -f {shlex.quote(hostname)}")
        if code == 0:
            with self._lock:
                self.targets.pop(hostname, None)
            self._emit("success", f"{hostname} deleted.")
            return True
        self._emit("error", f"Cannot delete {hostname}.")
        return False

    def clean_all(self) -> int:
        self._emit("info", "Cleaning up all lab targets...")
        out, _, code = self._docker(
            "ps -a --filter 'name=target-' --format '{{.Names}}'",
            silent=True
        )
        if code != 0:
            return 0

        targets = [l.strip() for l in out.splitlines() if l.strip()]
        if not targets:
            self._emit("info", "No target containers found.")
            return 0

        count = 0
        for name in targets:
            _, _, code = self._docker(f"rm -f {shlex.quote(name)}")
            if code == 0:
                count += 1
                self._emit("info", f"  Deleted: {name}")
                with self._lock:
                    self.targets.pop(name, None)

        self._emit("success", f"Cleanup complete: {count} container(s) removed.")
        return count

    # -------------------------------------------------------------------------
    # Report
    # -------------------------------------------------------------------------

    def get_report(self) -> Dict:
        return {
            "generated_at": datetime.now().isoformat(),
            "docker_host": self.docker_host,
            "network": self.network,
            "targets": list(self.targets.values()),
        }

    def save_report(self, filepath: Optional[str] = None) -> str:
        if not filepath:
            filepath = f"Mission_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.get_report(), f, indent=2, ensure_ascii=False)
        self._emit("success", f"Report saved: {filepath}")
        return filepath
