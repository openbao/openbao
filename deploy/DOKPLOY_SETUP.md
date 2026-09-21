# Dokploy par OpenBao Setup & Deployment Guide 🤖

Yeh guide aapko Dokploy me Docker Compose ke through OpenBao (Vault open-source fork) ko aasani se host karne me madad karegi.

---

## 1. Directory Structure

Aapke project me yeh files ready hain:
- [docker-compose.yml](file:///Volumes/DATA/01%20-%20Projects/OPS%20Tracker%20&%20Finance/02%20-%20Code/HQ%20Websites%20&%20Tools/01-%20Working%20/openbao-main/docker-compose.yml)
- [deploy/config.hcl](file:///Volumes/DATA/01%20-%20Projects/OPS%20Tracker%20&%20Finance/02%20-%20Code/HQ%20Websites%20&%20Tools/01-%20Working%20/openbao-main/deploy/config.hcl)
- [.env.example](file:///Volumes/DATA/01%20-%20Projects/OPS%20Tracker%20&%20Finance/02%20-%20Code/HQ%20Websites%20&%20Tools/01-%20Working%20/openbao-main/.env.example)

---

## 2. Dokploy Deployment (Method A - Git Repository) [Recommended]

Agar aapka repo GitHub/GitLab par push kiya hua hai:

1. **Dokploy Dashboard** open karein.
2. **Projects** me jakar ek naya Project banayein ya existing project select karein.
3. **Create Service** -> **Compose** select karein.
4. **Source** me **Git** select karein aur apna repository link karein:
   - Branch: `main`
   - Compose Path: `docker-compose.yml`
5. **Environment Variables** tab me jayein aur apna domain add karein:
   ```env
   DOMAIN=vault.yourdomain.com
   ```
6. **Domains** tab me jayein:
   - Click **Add Domain**
   - Host: `vault.yourdomain.com` (apna actual domain/subdomain dalein)
   - Service: `openbao`
   - Container Port: `8200`
   - HTTPS / Certificate: Enable (Let's Encrypt automatic SSL generate karega)
7. **Deploy** button par click karein.

---

## 3. Dokploy Deployment (Method B - Raw Compose Inline Editor)

Agar aap Git ke bina seedha Dokploy ke UI me compose file paste karke chalana chahte hain:

Dokploy me **Compose** -> **Raw** select karke yeh YAML paste karein:

```yaml
services:
  openbao:
    image: openbao/openbao:latest
    restart: unless-stopped
    cap_add:
      - IPC_LOCK
    command:
      - server
      - -config=/openbao/config
    environment:
      - BAO_REDIRECT_ADDR=https://vault.yourdomain.com
      - |
        BAO_LOCAL_CONFIG={
          "ui": true,
          "disable_mlock": true,
          "listener": {
            "tcp": {
              "address": "0.0.0.0:8200",
              "tls_disable": true
            }
          },
          "storage": {
            "raft": {
              "path": "/openbao/file",
              "node_id": "openbao_node_1"
            }
          },
          "api_addr": "https://vault.yourdomain.com",
          "cluster_addr": "http://127.0.0.1:8201"
        }
    expose:
      - "8200"
    volumes:
      - openbao-data:/openbao/file
    networks:
      - dokploy-network

networks:
  dokploy-network:
    external: true

volumes:
  openbao-data:
```

> **Note:** `https://vault.yourdomain.com` ki jagah apna actual domain replace karein.

---

## 4. DNS Configuration

Apne DNS provider (Cloudflare, Namecheap, GoDaddy, etc.) me ek **A Record** banayein:
- **Type**: `A`
- **Name**: `vault` (ya jo bhi subdomain ho)
- **IPv4 Address**: Aapke Dokploy VPS ka Public IP address
- **Proxy status**: DNS Only (recommended for initial setup) ya Cloudflare Proxied with Full (Strict) SSL.

---

## 5. First Time Setup: Initialize & Unseal OpenBao

Jab container deploy ho jaye:

1. Browser me open karein: `https://vault.yourdomain.com/ui`
2. Aapko **Initialize OpenBao** screen dikhegi:
   - **Key shares**: e.g. `5` (ya testing ke liye `1`)
   - **Key threshold**: e.g. `3` (ya testing ke liye `1`)
3. **Initialize** par click karein.
4. ⚠️ **IMPORTANT**: Screen par aane wali **Unseal Keys** aur **Initial Root Token** ko copy karke kisi secure jagah (e.g. Password Manager) save kar lein! Yeh dobara nahi dikhayi degi.
5. **Continue to Unseal** par click karein aur required Unseal Key(s) enter karein.
6. OpenBao unseal ho jane ke baad Root Token se login karein!
