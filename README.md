# Bjorn Chaos Lab

Automated vulnerable machine deployer for penetration testing training and CTF challenges. Deploys Docker containers with multiple configurable attack surfaces over SSH, managed through a web UI with real-time feedback.

## Features

- **Multiple vulnerability scenarios**: SQL injection, local file inclusion, command injection, unrestricted file upload, misconfigured services (FTP, SMB, MySQL, SSH, Telnet)
- **Privilege escalation challenges**: SUID binaries (GTFOBins), misconfigured sudo, writable cron jobs
- **Three difficulty levels**: Easy (weak passwords, obvious flags), Medium (moderate complexity, enumeration required), Hard (strong passwords, chained exploits)
- **Real-time web UI**: Deploy, monitor, and manage targets from a browser with live console output via Server-Sent Events
- **Flag system**: Each scenario plants `BJORN_CTF_*` flags that can be validated through the UI
- **Credential export**: Download or copy `users.txt` and `passwords.txt` for dictionary attacks
- **Credential upload**: Push collected credentials to a remote machine via SSH (e.g., a Bjorn device for automated attacks)
- **Optional API authentication**: Bearer token support for securing the management API
- **Resource limits**: Memory and CPU constraints on containers to prevent host saturation

## Architecture

```
bjorn-lab/
  lab_engine.py        Core deployment engine (SSH + Docker orchestration)
  lab_server.py        REST API + SSE web server (Python stdlib)
  lab-image/
    Dockerfile         Ubuntu 22.04 victim image with all services
    start.sh           Service initialization script
  web/
    index.html         Web UI
    style.css          Y2K terminal theme
    app.js             Frontend logic (vanilla JS, zero dependencies)
```

**Backend**: Python 3.8+ with `paramiko` for SSH. No web framework -- uses Python's built-in `http.server` with threading.

**Frontend**: Vanilla JavaScript with SSE for real-time log streaming. No build step, no dependencies.

**Container platform**: Docker with macvlan networking for realistic network-level attack simulation.

## Prerequisites

- Python 3.8+
- A Docker host accessible via SSH (Linux server, Synology NAS, etc.)
- Docker installed on the remote host
- A macvlan network configured on the Docker host

## Setup

### 1. Install Python dependencies

```bash
pip install paramiko
```

### 2. Configure the Docker host

On the remote Docker host, create a macvlan network:

```bash
docker network create -d macvlan \
  --subnet=192.168.1.0/24 \
  --gateway=192.168.1.1 \
  -o parent=eth0 \
  macvlan_zombieland
```

Adjust `--subnet`, `--gateway`, and `-o parent` to match your network configuration. The interface name (`eth0`) must be the host's physical network interface.

### 3. Build the victim image

Copy the `lab-image/` directory to the Docker host, then build:

```bash
cd /path/to/lab-image
docker build -t bjorn-victim .
```

On a Synology NAS, the typical path would be `/volume1/docker/lab-image/`.

### 4. Start the server

Basic usage:

```bash
python lab_server.py --port 5000
```

With auto-connect to Docker host:

```bash
python lab_server.py \
  --port 5000 \
  --docker-host 192.168.1.75 \
  --docker-user myuser \
  --docker-password mypassword \
  --network macvlan_zombieland
```

With API token authentication:

```bash
python lab_server.py --port 5000 --api-token my-secret-token
```

Or via environment variable:

```bash
export BJORNLAB_API_TOKEN=my-secret-token
python lab_server.py --port 5000
```

### 5. Open the web UI

Navigate to `http://localhost:5000` in your browser. If you did not use `--docker-host` flags, enter the Docker host credentials in the connection panel.

## Usage

### Deploying targets

1. Connect to your Docker host through the web UI (or use CLI flags for auto-connect)
2. Select a deployment mode:
   - **Random**: Mix of scenarios selected randomly
   - **Web**: Web-focused challenges (admin panels, SQLi, LFI, command injection, file upload)
   - **Database**: MySQL with fake corporate data and flags
   - **Network**: SMB shares and FTP with planted credentials
   - **Full**: All available scenarios
3. Select a difficulty level (Easy / Medium / Hard)
4. Set the number of targets (1-10)
5. Click Deploy

### Difficulty levels

| Level  | Passwords       | Scenarios                                                       | Flags                    |
|--------|-----------------|----------------------------------------------------------------|--------------------------|
| Easy   | Weak (common)   | Web, DB, SMB, FTP                                               | Plaintext, obvious       |
| Medium | 10-char random  | + SQLi, LFI, SUID privesc, git exposure, path traversal        | Requires enumeration     |
| Hard   | 16-char complex | + CMDi, file upload, SSRF, PATH/sudo/cron privesc, SSH key leak | Requires exploitation    |

### Vulnerability scenarios

| Scenario         | Description                                                         | Access       |
|------------------|---------------------------------------------------------------------|--------------|
| Web Admin Panel  | Fake login form with weak credentials, flag in robots.txt           | HTTP :80     |
| SQL Injection    | Vulnerable login page (string concatenation), flag in secrets table | HTTP :80     |
| Local File Incl. | PHP page with `?page=` parameter, flag in `/etc/bjorn_secret`      | HTTP :80     |
| Command Inject.  | Ping tool vulnerable to `;` and `\|` injection                     | HTTP :80     |
| File Upload      | Unrestricted PHP upload, web shell to read flag                     | HTTP :80     |
| SSRF             | URL fetcher reaching internal service on localhost:9999             | HTTP :80     |
| Path Traversal   | File download endpoint with `../` directory traversal              | HTTP :80     |
| Git Exposure     | Exposed `.git` directory with credentials in commit history         | HTTP :80     |
| MySQL Database   | Corporate database with employees and admin flag in pass_hash       | MySQL :3306  |
| SMB Share        | Guest-accessible public share with flag file + hidden home files    | SMB :445     |
| FTP              | FTP access with planted credential backup file                     | FTP :21      |
| SUID Privesc     | `find` binary set as SUID, root-only flag in `/root/`              | SSH :22      |
| Sudo Privesc     | User can `sudo vim` without password, root-only flag               | SSH :22      |
| Cron Privesc     | World-writable script in root crontab, root-only flag              | SSH :22      |
| PATH Hijacking   | SUID binary calling command without full path, writable PATH dir   | SSH :22      |
| SSH Key Leak     | Root private key left in web root and home directory               | HTTP + SSH   |

### Flag validation

Submit captured flags (`BJORN_CTF_*` format) in the Flag Validation panel. The system checks against all deployed targets and returns the source hostname and location.

### Credential upload

The credential upload panel pushes all unique usernames and passwords from deployed targets to a remote machine via SSH. This is designed for feeding wordlists to automated attack tools.

Default target: `192.168.1.66` / user `bjorn` / password `bjorn` / path `/home/bjorn/Bjorn/data/input/dictionary/`

Files are appended without duplicates (existing entries are preserved).

## API Reference

All endpoints accept and return JSON. If API token authentication is enabled, include `Authorization: Bearer <token>` in request headers.

| Method | Endpoint            | Description                          |
|--------|---------------------|--------------------------------------|
| GET    | `/api/status`       | Connection status and image check    |
| POST   | `/api/connect`      | Connect to Docker host               |
| POST   | `/api/deploy`       | Deploy targets (count, mode, difficulty) |
| GET    | `/api/targets`      | List all deployed targets            |
| GET    | `/api/targets/:name`| Get specific target details          |
| POST   | `/api/delete`       | Delete a single target               |
| POST   | `/api/clean`        | Delete all targets                   |
| POST   | `/api/validate`     | Validate a CTF flag                  |
| POST   | `/api/upload-creds` | Upload credentials to remote machine |
| GET    | `/api/report`       | Download mission report (JSON)       |
| GET    | `/api/events`       | SSE stream for live console output   |

### Example: Deploy via curl

```bash
curl -X POST http://localhost:5000/api/deploy \
  -H "Content-Type: application/json" \
  -d '{"count": 3, "mode": "random", "difficulty": "medium"}'
```

### Example: Validate a flag

```bash
curl -X POST http://localhost:5000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"flag": "BJORN_CTF_ABC123XYZ..."}'
```

## Synology NAS Setup

1. Enable SSH in **Control Panel > Terminal & SNMP > Terminal**
2. Install Docker from **Package Center**
3. Upload the `lab-image/` directory to your NAS (e.g., via File Station to `/volume1/docker/lab-image/`)
4. SSH into the NAS and build the image:
   ```bash
   cd /volume1/docker/lab-image
   sudo docker build -t bjorn-victim .
   ```
5. Create the macvlan network:
   ```bash
   sudo docker network create -d macvlan \
     --subnet=192.168.1.0/24 \
     --gateway=192.168.1.1 \
     -o parent=eth0 \
     macvlan_zombieland
   ```
6. Run the server from your local machine pointing to the NAS IP

The Docker binary on Synology is typically at `/usr/local/bin/docker` -- the engine auto-detects this.

## Security Notes

- This tool is designed for **authorized security testing and training only**
- Never expose the web server to untrusted networks without API authentication enabled
- Containers are intentionally vulnerable -- do not deploy them on production networks
- The SSH password for the Docker host is stored in memory during the server session
- Set `--api-token` or `BJORNLAB_API_TOKEN` when running on shared networks

## License

MIT
