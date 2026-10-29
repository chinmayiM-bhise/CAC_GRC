#!/usr/bin/env bash
# ==============================================================================
# CAC-GRC Target Linux VM Bootstrap Script (Ubuntu 22.04 / 24.04 LTS)
# Configures PAM Lockout, auditd kernel rules, SSH hardening, and Auditor user.
# ==============================================================================

set -euo pipefail

echo ">>> [1/5] Updating packages and installing auditd & PAM modules..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins libpam-modules libpam-faillock openssh-server

echo ">>> [2/5] Creating dedicated auditor user..."
if ! id -u auditor >/dev/null 2>&1; then
    useradd -m -s /bin/bash auditor
    echo "auditor:auditor123" | chpasswd
    usermod -aG sudo auditor
    echo "auditor ALL=(ALL) NOPASSWD: /usr/sbin/ausearch, /usr/sbin/auditctl, /usr/bin/systemctl" > /etc/sudoers.d/auditor
    chmod 0440 /etc/sudoers.d/auditor
fi

# Create canary account for testing lockout probes
if ! id -u audit_canary >/dev/null 2>&1; then
    useradd -m -s /bin/bash audit_canary
    echo "audit_canary:CanaryPass2026!" | chpasswd
fi

echo ">>> [3/5] Configuring PAM Lockout (5 attempts, 15m lockout)..."
cat << 'EOF' > /etc/security/faillock.conf
# Managed by CAC-GRC Compliance Baseline
dir = /var/run/faillock
audit
silent
deny = 5
fail_interval = 900
unlock_time = 900
EOF

# Ensure PAM common-auth includes faillock
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    pam-auth-update --enable faillock || true
fi

echo ">>> [4/5] Hardening OpenSSH Configuration..."
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

echo ">>> [5/5] Configuring auditd Kernel Rules..."
cat << 'EOF' > /etc/audit/rules.d/cac-grc.rules
## Monitor modifications to sensitive authentication files (NIST AU-2 / ISO A.8.15)
-w /etc/shadow -p wa -k shadow_watch
-w /etc/passwd -p wa -k passwd_watch
-w /etc/security/faillock.conf -p wa -k pam_config_watch
-w /etc/ssh/sshd_config -p wa -k sshd_config_watch

## Monitor privilege escalation commands
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec
EOF

augenrules --load || systemctl restart auditd
systemctl enable auditd
systemctl start auditd

echo "======================================================================"
echo ">>> CAC-GRC Target Linux VM Bootstrap Complete!"
echo ">>> IP Address: $(hostname -I | awk '{print $1}')"
echo ">>> Auditor Account: auditor (password: auditor123)"
echo "======================================================================"
