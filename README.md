# cloud
Script to ease ubuntu servers setup




```bash
#!/bin/bash

# Title: Auto-Secure Server Hardening Script
# Description:
# 1. Implements cloud-agnostic security measures
# 2. Requires manual cloud firewall configuration for SSH
# 3. Installs comprehensive security toolkit
# 4. Provides post-install audit commands
# Pre-requisites:
# - Generate SSH keys on your local machine: ssh-keygen -t ed25519
# - Configure cloud firewall to allow current IP + SSH port
# - Backup critical data before execution

cat << "EOF"

███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
        Cloud-Ready Server Hardening
EOF

# =====================
# INITIALIZATION
# =====================

# Check root privileges
if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Run with sudo/root privileges"
  exit 1
fi

# Initialize configuration
declare -A CONFIG=(
  ["SSH_PORT"]=""
  ["ADMIN_USER"]=""
 # ["AUTO_REBOOT_TIME"]="02:00"
  ["ENABLE_2FA"]=""
)

# =====================
# USER INPUT
# =====================

get_input() {
  clear
  echo "🛠️  Configuration (Follow Cloud Provider Guidelines)"
  echo "----------------------------------------------------"
  
  read -p "➤ New SSH Port (1024-49151): " CONFIG["SSH_PORT"]
  read -p "➤ Admin Username: " CONFIG["ADMIN_USER"]
  read -p "➤ Enable SSH 2FA? (y/n): " CONFIG["ENABLE_2FA"]
  
  echo -e "\n⚠️  Cloud Firewall Checklist:"
  echo "1. Create firewall rule for SSH port ${CONFIG["SSH_PORT"]}"
  echo "2. Whitelist your current IP address"
  echo "3. Remove default SSH (port 22) rules"
  read -n 1 -s -r -p $'\n▶ Press any key to acknowledge cloud setup'
}

validate_input() {
  [[ ${CONFIG["SSH_PORT"]} =~ ^[0-9]+$ ]] && 
  [ "${CONFIG["SSH_PORT"]}" -ge 1024 ] && 
  [ "${CONFIG["SSH_PORT"]}" -le 49151 ]
}

# =====================
# SECURITY FUNCTIONS
# =====================

system_update() {
  echo "🔁 Updating system & installing base packages..."
  apt update && apt full-upgrade -y
  apt install -y \
    ufw fail2ban unattended-upgrades \
    auditd lynis rkhunter clamav chkrootkit \
    apparmor apparmor-utils
}

configure_ssh() {
  echo "🔒 SSH Hardening..."
  # Backup original config
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
  
  sed -i "s/#Port 22/Port ${CONFIG["SSH_PORT"]}/" /etc/ssh/sshd_config
  sed -i "s/PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
  echo "AllowUsers ${CONFIG["ADMIN_USER"]}" >> /etc/ssh/sshd_config
  
  if [[ ${CONFIG["ENABLE_2FA"],,} == "y" ]]; then
    echo "🔐 Enabling 2FA..."
    apt install -y libpam-google-authenticator
    echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
    sed -i "s/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/" /etc/ssh/sshd_config
    echo "AuthenticationMethods publickey,keyboard-interactive" >> /etc/ssh/sshd_config
  fi
  
  systemctl restart sshd
}

setup_firewall() {
  echo "🔥 Configuring UFW (Application Layer)..."
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow http
  ufw allow https
  ufw --force enable
}

security_tools() {
  echo "🛡️  Deploying Security Stack..."
  
  # Fail2Ban
  cp /etc/fail2ban/jail.{conf,local}
  sed -i "s/port = ssh/port = ${CONFIG["SSH_PORT"]}/" /etc/fail2ban/jail.local
  systemctl restart fail2ban
  
  # Auditd
  systemctl enable auditd && systemctl start auditd
  
  # ClamAV
  freshclam && systemctl enable clamav-freshclam
  
  # AppArmor
  aa-enforce /etc/apparmor.d/*
}

# =====================
# MAIN EXECUTION
# =====================

get_input

if validate_input; then
  system_update
  configure_ssh
  setup_firewall
  security_tools
else
  echo "❌ Invalid SSH port! Use 1024-49151"
  exit 1
fi

# =====================
# POST-INSTALL GUIDANCE
# =====================

echo -e "\n✅ Hardening Complete!\n"
echo "Next Steps:"
echo "1. Test SSH access from whitelisted IP:"
echo "   ssh -p ${CONFIG["SSH_PORT"]} ${CONFIG["ADMIN_USER"]}@$(hostname -I | awk '{print $1}')"
echo "2. Security Audits:"
echo "   sudo lynis audit system"
echo "   sudo rkhunter --check --sk"
echo "   sudo clamscan -r / --move=/var/quarantine"
echo "3. Monitor logs:"
echo "   journalctl -u sshd -f"
echo "   fail2ban-client status"
echo "4. Update regularly:"
echo "   sudo apt update && sudo apt upgrade -y"
```

**Key Improvements**:

1. **Cloud-First Security Model**
```bash
# Before running:
# - Configure cloud firewall for SSH port
# - Whitelist your IP at cloud provider level
# - Remove default SSH port rules
```

2. **Comprehensive Security Stack**
```bash
# Installs:
- Lynis: System auditing
- ClamAV: Malware detection
- rkhunter: Rootkit scanner
- AppArmor: Mandatory access control
- auditd: System call monitoring
```

3. **Clear Post-Install Guidance**
```bash
# Post-execution checks:
- Test SSH access first!
- Run security audits
- Monitor Fail2Ban status
- Schedule regular scans
```

4. **Safety Measures**
```bash
# Includes:
- Config backups (sshd_config)
- Input validation
- No direct IP whitelisting (cloud responsibility)
- 2FA optional but recommended
```

**Usage Workflow**:
### On your local machine:

1. **Pre-Script Setup**
```bash

ssh-keygen -t ed25519 -C "admin@server"
ssh-copy-id -p CURRENT_SSH_PORT user@server
```
### On cloud platform:

1. Create firewall rule for new SSH port
2. Whitelist your current public IP
3. Delete default SSH (port 22) rule


2. **Script Execution**
```bash
chmod +x secure_server.sh
sudo ./secure_server.sh
```

3. **Post-Install Audit**
```bash
# Daily:
sudo lynis audit system
sudo freshclam && clamscan -r /home

# Weekly:
sudo rkhunter --update
sudo rkhunter --check --sk
```

**Security Philosophy**:
- Defense in depth with multiple layers
- Cloud-native firewall management
- Principle of least privilege
- Continuous monitoring setup
- Automated vulnerability scanning

This script implements enterprise-grade security while maintaining cloud platform compatibility. Always test in staging first!
