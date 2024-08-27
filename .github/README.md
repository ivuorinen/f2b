# ivuorinen/f2b

A fail2ban wrapper for easier management and listing of banned IP's in your jails.

Requires fail2ban to be installed and running. Should work on most Linux distributions.
Developed against `fail2ban` version 0.11.2 on Ubuntu 22.04.4 LTS using nvim.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/) ![GitHub file size in bytes](https://img.shields.io/github/size/ivuorinen/f2b/f2b)

## Installation

```bash
curl https://raw.githubusercontent.com/ivuorinen/f2b/main/f2b > f2b
chmod +x f2b
./f2b version
```

Requiements: `fail2ban` (duh), and few other default tools.
`awk`, `cat`, `date`, `grep`, `ls`, `sed`, `sort`, `tail`, `tr`, `wc`, and `zcat` should be installed.
Those are usually installed by default on most Linux distributions. The script will tell you if something is missing.

If running commands straight from the internet scares you (as it should) you can
open the f2b script in your favourite editor (or here in GitHub) and view the source.

I promise I'm not doing anything weird in the script.

## Usage

It uses several fail2ban commands to get the information it needs, so it needs to be run as root.

```bash
Usage: f2b [command] [options]
 list-jails             List all jails
 status all             Show status of all jails
 status [jail]          Show status of a specific jail
 banned                 Show all banned IP addresses with ban time left
 banned [jail]          Show all banned IP addresses with ban time left in a jail
 ban [ip]               Ban IP address in all jails
 ban [ip] [jail]        Ban IP address in a specific jail
 unban [ip]             Unban IP address in all jails
 unban [ip] [jail]      Unban IP address in a specific jail
 test [ip]              Test if IP address is banned
 logs                   Show fail2ban logs
 logs all [ip]          Show logs for a specific IP address in all jails
 logs [jail]            Show logs for a specific jail
 logs [jail] [ip]       Show logs for a specific jail and IP address
 logs-watch             Watch fail2ban logs
 logs-watch all [ip]    Watch logs for a specific IP address
 logs-watch [jail]      Watch logs for a specific jail
 logs-watch [jail] [ip] Watch logs for a specific jail and IP address
 test-filter [filter]   Test a fail2ban filter
 service start          Start fail2ban
 service stop           Stop fail2ban
 service restart        Restart fail2ban
 help                   Show help
 version                Show version
```

## Authors

- [@ivuorinen](https://github.com/ivuorinen)

## License

[MIT](https://choosealicense.com/licenses/mit/)

