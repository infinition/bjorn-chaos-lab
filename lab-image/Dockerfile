FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install target services and tools for attack scenarios
RUN apt-get update && apt-get install -y \
    openssh-server vsftpd mariadb-server samba apache2 \
    php libapache2-mod-php php-mysql \
    telnetd inetutils-inetd \
    python3 sudo net-tools curl iputils-ping \
    nano unzip zip netcat-openbsd \
    cron gcc make git php-curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Telnet via inetd (legacy attack surface)
RUN echo "telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.telnetd" >> /etc/inetd.conf

# SSH: allow root login + password auth
RUN mkdir -p /var/run/sshd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Apache: suppress ServerName warning + remove default page
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf \
    && rm -f /var/www/html/index.html

# MariaDB: ensure run directory exists
RUN mkdir -p /var/run/mysqld \
    && chown mysql:mysql /var/run/mysqld

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Expose attack surfaces
EXPOSE 22 21 80 445 3306 23

CMD ["/start.sh"]
