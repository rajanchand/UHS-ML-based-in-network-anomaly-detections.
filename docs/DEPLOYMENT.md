# Production Deployment Guide

Instructions for deploying Aegis in a production environment.

---

## 1. Prerequisites
Ensure the target server has:
* Linux OS (CentOS, Ubuntu, Debian, etc.)
* Docker installed (v20.10+)
* Docker Compose installed (v2.0+)

---

## 2. Setting up Environment File
Copy the environment template and modify credentials:
```bash
cp .env.example .env
nano .env
```
Ensure you change:
* `SECRET_KEY`: A long random string.
* `POSTGRES_PASSWORD`: A secure database password.
* `FLASK_ENV`: Set to `production`.

---

## 3. Deployment Steps
Launch containers in detached mode:
```bash
docker-compose -f docker-compose.yml up --build -d
```

Verify service containers are up:
```bash
docker-compose ps
```

---

## 4. Reverse Proxy & SSL (Optional)
To set up Let's Encrypt certificates (SSL) for HTTPS:
1. Install certbot on the host:
   ```bash
   sudo apt install certbot
   ```
2. Retrieve certificate:
   ```bash
   sudo certbot certonly --standalone -d yourdomain.com
   ```
3. Update `nginx.conf` to configure port 443 with certificate locations.
