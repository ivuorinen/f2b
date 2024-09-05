FROM lscr.io/linuxserver/fail2ban:latest

WORKDIR /app
COPY . /app

SHELL [ "/bin/bash" ]

