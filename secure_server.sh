#!/bin/bash
#
# Title: Auto-Secure Server Hardening Script
# Description:
#   1. Implements cloud-agnostic security measures
#   2. Requires manual cloud firewall configuration for SSH
#   3. Installs comprehensive security toolkit
#   4. Provides post-install audit commands
# Pre-requisites:
#   - Generate SSH keys on your local machine: ssh-keygen -t ed25519
#   - Configure cloud firewall to allow current IP + SSH port
#   - Backup critical data before execution
#
# Usage:
#   - By default, it runs in interactive mode (you will see all prompts).
#   - To force non-interactive mode, set INTERACTIVE_INSTALL="false".

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

# 1) Toggle this to "false" if you want to run fully non-interactively.
INTERACTIVE_INSTALL="true"

# Check root privileges
if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Run with sudo/root privileges"
  exit 1
fi

# Initialize configuration (using the default 'ubuntu' AWS user)
declare -A CONFIG=(
  ["SSH_PORT"]="1042"
  ["ADMIN_USER"]="ubuntu"
)

# =====================
# USER INPUT
# =====================

get_input() {
  clear
  echo "🛠️  Configuration (Follow Cloud Provider Guidelines)"
  echo "----------------------------------------------------"
  
  # Prompt for SSH port if not set
  if [ -z "${CONFIG["SSH_PORT"]}" ]; then
    read -p "➤ New SSH Port (1024-49151): " CONFIG["SSH_PORT"]
  fi

  # Prompt for admin user if not set (default to 'ubuntu' on AWS)
  if [ -z "${CONFIG["ADMIN_USER"]}" ]; then
    read -p "➤ Admin Username (Default is ubuntu on AWS): " CONFIG["ADMIN_USER"]
  fi
  
  echo -e "\n⚠️  Cloud Firewall Checklist:"
  echo "1. Create firewall rule for SSH port ${CONFIG["SSH_PORT"]}"
  echo "2. Whitelist your current IP address"
  echo "3. Remove default SSH (port 22) rules"
  read -n 1 -s -r -p $'\n▶ Press any key to acknowledge cloud setup'
}

validate_input() {
  # Basic numeric check for port range
  [[ ${CONFIG["SSH_PORT"]} =~ ^[0-9]+$ ]] && 
  [ "${CONFIG["SSH_PORT"]}" -ge 1024 ] && 
  [ "${CONFIG["SSH_PORT"]}" -le 49151 ]
}

# =====================
# SECURITY FUNCTIONS
# =====================

system_update() {
  echo "🔁 Updating system & installing base packages..."

  if [ "$INTERACTIVE_INSTALL" = "true" ]; then
    # -- Interactive mode: see any prompts
    # Remove -y so that apt can ask you if it needs anything
    # If a package strongly requires input, you'll see it
    apt update
    apt full-upgrade
    apt install \
      ufw fail2ban unattended-upgrades \
      auditd lynis rkhunter clamav chkrootkit \
      apparmor apparmor-utils
  else
    # -- Non-interactive mode
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get -y -o Dpkg::Options::="--force-confdef" \
              -o Dpkg::Options::="--force-confold" \
              full-upgrade
    apt-get -y -o Dpkg::Options::="--force-confdef" \
              -o Dpkg::Options::="--force-confold" \
              install \
              ufw fail2ban unattended-upgrades \
              auditd lynis rkhunter clamav chkrootkit \
              apparmor apparmor-utils
  fi
}

configure_ssh() {
  echo "🔒 SSH Hardening..."
  
  # Backup original config
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
  
  # Update SSH port line (remove any #Port or Port lines, replace with our custom port)
  sed -i 's/^#\?Port .*/Port '"${CONFIG["SSH_PORT"]}"'/' /etc/ssh/sshd_config
  
  # Disable root login
  sed -i "s/PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
  
  # Restrict SSH to a specific user (default ubuntu on AWS)
  echo "AllowUsers ${CONFIG["ADMIN_USER"]}" >> /etc/ssh/sshd_config
  
  # Test SSH config before applying
  if ! sshd -t -f /etc/ssh/sshd_config; then
    echo "❌ SSH config test failed. Restoring backup..."
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    exit 1
  fi
  
  # Open new SSH port in firewall
  echo "🔥 Opening SSH port ${CONFIG["SSH_PORT"]} in UFW..."
  ufw allow "${CONFIG["SSH_PORT"]}/tcp"
  ufw reload
  
  # Restart SSH service
  echo "🔄 Restarting SSH service..."
  systemctl restart sshd
  
  # Verify SSH is running
  if ! systemctl is-active --quiet sshd; then
    echo "❌ SSH service failed to start. Restoring backup..."
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    systemctl restart sshd
    exit 1
  fi
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
