#!/bin/bash
# Bjorn Chaos Lab -- Victim Container Startup
# Initializes MariaDB, starts all attack surface services.

set -e

echo "[*] Starting Bjorn Chaos Lab victim container..."

# --- MariaDB ---
echo "[*] Initializing MariaDB..."

if [ ! -d "/var/lib/mysql/mysql" ]; then
    echo "[*] First boot -- running mysql_install_db..."
    mysql_install_db --user=mysql --datadir=/var/lib/mysql > /dev/null 2>&1
    echo "[+] MariaDB data directory initialized."
fi

chown -R mysql:mysql /var/lib/mysql
chown -R mysql:mysql /var/run/mysqld 2>/dev/null || mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld

mysqld_safe --skip-syslog &
MYSQL_PID=$!

echo -n "[*] Waiting for MySQL..."
MYSQL_READY=0
for i in $(seq 1 30); do
    if mysqladmin ping --silent 2>/dev/null; then
        MYSQL_READY=1
        break
    fi
    echo -n "."
    sleep 1
done

if [ "$MYSQL_READY" -eq 1 ]; then
    echo " OK"
    touch /var/run/mysql-ready
    echo "[+] MariaDB is ready (PID: $MYSQL_PID)."
else
    echo " TIMEOUT"
    echo "[!] MariaDB failed to start within 30s."
fi

# --- SSH ---
echo "[*] Starting SSH..."
service ssh start || echo "[!] SSH failed"

# --- FTP ---
echo "[*] Starting vsftpd..."
service vsftpd start || echo "[!] vsftpd failed"

# --- Samba ---
echo "[*] Starting Samba..."
service smbd start || echo "[!] Samba failed"

# --- Apache ---
echo "[*] Starting Apache..."
service apache2 start || echo "[!] Apache failed"

# --- Telnet (inetd) ---
echo "[*] Starting inetd (Telnet)..."
/usr/sbin/inetd || echo "[!] inetd failed"

# --- Cron ---
echo "[*] Starting cron..."
service cron start || echo "[!] Cron failed"

echo "============================================="
echo "[+] All services started. Container is ready."
echo "============================================="

exec tail -f /dev/null
