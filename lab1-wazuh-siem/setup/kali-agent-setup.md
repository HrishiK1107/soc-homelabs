# Kali Agent Setup — Kali GNU/Linux 2026.2

## Prerequisites
- Kali Linux VM
- Wazuh Manager running on 192.168.234.138
- Both VMs on same VMware NAT network

---

## Step 1 — Add Wazuh Repository
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update
```

## Step 2 — Install Agent
```bash
WAZUH_MANAGER="192.168.234.138" WAZUH_AGENT_NAME="kali" sudo apt-get install wazuh-agent -y
```

## Step 3 — Start Agent
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

## Step 4 — Verify Running
```bash
sudo systemctl status wazuh-agent
```
Must show `active (running)`.

## Step 5 — Verify on Dashboard

Dashboard → **Agents** → `kali` should show **Active**.

---

## Key Log Sources Ingested from Kali
| Log File | Content |
|----------|---------|
| /var/log/auth.log | PAM, sudo, su events |
| /var/log/syslog | System events |

---

## Result
Kali agent deployed and active. Linux auth logs flowing to Wazuh — sudo, PAM, and login events visible in dashboard.