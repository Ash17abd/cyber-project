# 🚀 Cloud Deployment Guide for Cyber Sentinel

This guide provides step-by-step instructions to deploy **Cyber Sentinel SOC Threat Analysis Dashboard** on **Streamlit Community Cloud**, **Vercel**, and **Render** so that it remains publicly accessible 24/7.

---

## 🌟 Quick Overview: Hosting Options

| Platform | Cost | Uptime / Sleep | Setup Time | Custom Domain | Recommended For |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Streamlit Community Cloud** | **100% Free** | **24/7 (Always Live)** | **2 minutes** | Yes (`*.streamlit.app`) | **Official Streamlit Python Host** |
| **Vercel Cloud** | **100% Free** | **24/7 (Global Edge)** | **2 minutes** | Yes (`*.vercel.app`) | **Serverless API + Command Portal** |
| **Render.com** | Free tier | Spins down after 15m idle | 2 minutes | Yes (`*.onrender.com`) | Full Web Service / Blueprint |
| **Hugging Face Spaces** | 100% Free | 24/7 (16GB RAM) | 3 minutes | Yes (`hf.space`) | Generous Free RAM (16 GB) |
| **Self-Hosted VPS (Docker)** | VPS | True 24/7 (Always on) | 10 minutes | Custom Domain + SSL | Full Enterprise Control |

---

## ⚡ Method 1: Deploy on Streamlit Community Cloud (Recommended)

Streamlit Community Cloud is Snowflake's official free hosting platform for Streamlit applications. It provides direct GitHub synchronization and continuous deployments on every `git push`.

### Step 1: Push Your Code to GitHub
Ensure all your files and recent updates are committed and pushed to your GitHub repository:
```bash
git add .
git commit -m "feat: enhance copilot, geolocation detection, and vercel deployment"
git push origin main
```

### Step 2: Connect to Streamlit Community Cloud
1. Go to **[share.streamlit.io](https://share.streamlit.io/)**.
2. Sign in with your **GitHub account**.
3. In the top-right corner, click the **"New app"** button.

### Step 3: Configure Deployment
Fill out the 3 fields:
- **Repository:** `Ash17abd/cyber-sentinel` (or select from your repository dropdown)
- **Branch:** `main`
- **Main file path:** `app.py`
- **App URL (Custom Subdomain):** Enter your preferred custom subdomain, e.g. `cyber-sentinel-soc`

### Step 4: Add Optional Environment Secrets (API Keys)
If you want to configure cloud AI API keys (Google Gemini, AbuseIPDB, VirusTotal):
1. In the deployment dialog, click **Advanced settings...**
2. Paste the following into the **Secrets** box:
```toml
# Optional API Keys for Live Cloud Intelligence
GEMINI_API_KEY = "AIzaSy..."
VIRUSTOTAL_API_KEY = ""
ABUSEIPDB_API_KEY = ""
ALIENVAULT_OTX_KEY = ""
ADMIN_PASSWORD = "Admin@12345"
```
*(If no keys are provided, Cyber Sentinel operates seamlessly using our autonomous offline reasoning engine and built-in cached threat intelligence.)*

### Step 5: Launch!
Click **Deploy!**. Streamlit Cloud will install dependencies from `requirements.txt` and launch your dashboard at:
```text
https://cyber-sentinel-soc.streamlit.app
```

---

## ⚡ Method 2: Deploy on Vercel (Edge Portal + Serverless API)

Our repository includes a pre-configured `vercel.json` blueprint, a Python serverless REST API (`api/index.py`), and a cyberpunk command portal (`public/index.html`) that embeds or connects to your Streamlit instance.

### Option A: Deploy via Vercel Web Dashboard (1-Click)
1. Go to **[vercel.com](https://vercel.com/)** and log in with GitHub.
2. Click **"Add New..."** ➔ **"Project"**.
3. Under **"Import Git Repository"**, select `Ash17abd/cyber-sentinel`.
4. Vercel automatically detects the root configuration and `vercel.json`:
   - **Framework Preset:** `Other` (detected automatically)
   - **Root Directory:** `./`
5. Click **Deploy**.
6. Within ~60 seconds, your application is live at:
```text
https://cyber-sentinel.vercel.app
```

### Option B: Deploy via Vercel CLI
If you prefer deploying from your terminal:
```bash
# 1. Install Vercel CLI globally
npm install -g vercel

# 2. Login to your Vercel account
vercel login

# 3. Deploy to production
vercel --prod
```

### Available Vercel Endpoints:
- **Portal & Streamlit Viewer:** `https://<your-project>.vercel.app/`
- **Serverless Health Check:** `https://<your-project>.vercel.app/api/health`
- **Edge IP/Threat Lookup:** `https://<your-project>.vercel.app/api/lookup?ip=198.51.100.45`
- **Threat Catalog API:** `https://<your-project>.vercel.app/api/threats`

---

## ⚡ Method 3: Deploy on Render.com (1-Click Blueprint)

Render offers free web service hosting using our pre-configured `render.yaml` Blueprint.

### 1-Click Instant Blueprint Deployment
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Ash17abd/cyber-sentinel)

1. Click the button above or visit:
   ```text
   https://render.com/deploy?repo=https://github.com/Ash17abd/cyber-sentinel
   ```
2. Sign in to [Render](https://dashboard.render.com/) with GitHub.
3. Render auto-configures:
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `streamlit run app.py --server.port=$PORT --server.address=0.0.0.0 --server.enableCORS=false --server.enableXsrfProtection=false --server.headless=true`
   - **Health Check Path**: `/_stcore/health`
4. Click **Apply** to deploy!

---

## ⚡ Method 4: Deploy with Docker on Any Cloud VPS (AWS, DigitalOcean, Oracle)

If you run a Linux VM:
```bash
git clone https://github.com/Ash17abd/cyber-sentinel.git
cd cyber-sentinel
docker compose up -d --build
```
The dashboard will run on port `8501` with `restart: unless-stopped`.

---

## 🔐 Credentials for Public Reviewers

| Role | Username | Password |
| :--- | :--- | :--- |
| **Lead Administrator** | `admin` | `Admin@12345` |
| **Security Analyst** | `analyst` | `Analyst@12345` |
| **Incident Auditor** | `viewer` | `Viewer@12345` |
