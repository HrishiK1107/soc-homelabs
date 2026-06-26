# Wazuh Manager Setup — Ubuntu Server 22.04

## Prerequisites
- Ubuntu Server 22.04 LTS
- Minimum 4GB RAM, 2 vCPUs
- VMware NAT network adapter
- Internet access for package download

---

## Step 1 — System Update
```bash
sudo apt-get update && sudo apt-get upgrade -y
```

## Step 2 — Download Wazuh Installer
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
```

## Step 3 — Configure config.yml
```yaml
nodes:
  indexer:
    - name: node-1
      ip: "192.168.234.138"
  server:
    - name: wazuh-1
      ip: "192.168.234.138"
  dashboard:
    - name: dashboard
      ip: "192.168.234.138"
```

## Step 4 — Run Installer
```bash
sudo bash wazuh-install.sh -a
```
> Save the admin password printed at the end of installation.

## Step 5 — Verify Services
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-dashboard
sudo systemctl status wazuh-indexer
```
All three must show `active (running)`.

## Step 6 — Access Dashboard

```
https://192.168.234.138:443

Username: admin
Password: <from install output>
```
---

## Firewall Rules
```bash
sudo ufw allow 1514
sudo ufw allow 1515
sudo ufw allow 443
sudo ufw reload
```

---

## Result
Wazuh all-in-one deployed — manager, indexer, and dashboard running on single Ubuntu VM.