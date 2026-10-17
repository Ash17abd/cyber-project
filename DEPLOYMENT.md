# 🚀 24/7 Cloud Deployment Guide for Cyber Sentinel

This guide provides step-by-step instructions to deploy the **Cyber Sentinel SOC Threat Analysis Dashboard** on **Render.com** (and other leading cloud platforms) so that it remains publicly accessible 24/7.

---

## 🌟 Quick Overview: Hosting Options

| Platform | Cost | Uptime / Sleep | Setup Time | Custom Domain | Recommended For |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Render.com** | **Free tier** | Spins down after 15m idle (auto-wakes) | **2 minutes** | Yes (`*.onrender.com`) | **Full Web Service / Blueprint** |
| **Streamlit Community Cloud** | **100% Free** | 24/7 (Auto-wakes instantly) | **2 minutes** | Yes (`*.streamlit.app`) | Fast Python Streamlit Host |
| **Hugging Face Spaces** | **100% Free** | 24/7 (No sleep, 16GB RAM) | **3 minutes** | Yes (`hf.space`) | Generous Free RAM (16 GB) |
| **Self-Hosted VPS (Docker)** | Free Tier / VPS | True 24/7 (Always on) | **10 minutes** | Custom Domain + Let's Encrypt | Enterprise / Full Control |

---

## ⚡ Method 1: Deploy on Render.com (Recommended)

Render offers free web service hosting with automatic HTTPS, continuous deployment on every `git push`, and instant provisioning using our pre-configured `render.yaml` Blueprint.

### Option A: 1-Click Instant Blueprint Deployment

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Ash17abd/cyber-sentinel)

1. Click the button above or visit:
   ```text
   https://render.com/deploy?repo=https://github.com/Ash17abd/cyber-sentinel
   ```
2. Sign in to [Render](https://dashboard.render.com/) (using GitHub or Google).
3. Render automatically detects the `render.yaml` Blueprint:
   - **Service Name**: `cyber-sentinel-soc`
   - **Environment**: `Python 3.11.8`
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `streamlit run app.py --server.port=$PORT --server.address=0.0.0.0 --server.enableCORS=false --server.enableXsrfProtection=false --server.headless=true`
   - **Health Check Path**: `/_stcore/health`
4. Click **Apply**. Render will clone your repository, build the dependencies, and deploy your live dashboard!

---

### Option B: Manual Web Service Setup on Render

If you prefer to configure the Web Service manually from the Render dashboard:

1. Log in to [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** in the top navigation bar and select **Web Service**.
3. Under **Connect a repository**, choose `Ash17abd/cyber-sentinel` (if your GitHub account is connected) or paste the public Git repo URL:
   ```text
   https://github.com/Ash17abd/cyber-sentinel.git
   ```
4. Configure the Web Service settings:
   - **Name**: `cyber-sentinel-soc` (or your preferred name)
   - **Region**: Choose the closest region (e.g., `Oregon (US West)`, `Frankfurt (EU)`, or `Singapore (Asia)`)
   - **Branch**: `main`
   - **Root Directory**: *(leave blank)*
   - **Runtime**: `Python`
   - **Build Command**:
     ```bash
     pip install --upgrade pip && pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     streamlit run app.py --server.port=$PORT --server.address=0.0.0.0 --server.enableCORS=false --server.enableXsrfProtection=false --server.headless=true
     ```
   - **Instance Type**: Select **Free** ($0/month)
5. Under **Advanced**:
   - **Health Check Path**: `/_stcore/health`
   - **Auto-Deploy**: `Yes`
   - **Environment Variables** (Optional):
     | Variable | Recommended Value | Note |
     | :--- | :--- | :--- |
     | `PYTHON_VERSION` | `3.11.8` | Ensures fast, binary-wheel Python package install |
     | `PYTHONUNBUFFERED` | `1` | Real-time console logs in Render log viewer |
     | `ADMIN_PASSWORD` | *(Optional custom)* | Default: `Admin@12345` |
     | `VIRUSTOTAL_API_KEY` | *(Optional)* | For live IP/Hash threat intelligence |
6. Click **Create Web Service**.

Your live URL will look like:
```text
https://cyber-sentinel-soc.onrender.com
```

> [!TIP]
> **Keeping Render Free Tier 24/7 Active (No Spin-down):**
> Free services on Render spin down after 15 minutes of zero traffic, taking ~30–50 seconds to wake on the next visit. To keep it warm 24/7 for zero cost, add a free monitor on [UptimeRobot.com](https://uptimerobot.com/) or [cron-job.org](https://cron-job.org/) that sends an HTTP GET request to `https://<your-service>.onrender.com/_stcore/health` every 10 minutes.

---

## 🥈 Method 2: Streamlit Community Cloud

Streamlit Community Cloud is Snowflake's official free hosting platform for Streamlit applications.

### Step 1: Deploy on Streamlit Cloud
1. Go to [share.streamlit.io](https://share.streamlit.io/).
2. Click **Sign in with GitHub**.
3. Click the **"New app"** button.
4. Fill in the form:
   - **Repository**: `Ash17abd/cyber-sentinel`
   - **Branch**: `main`
   - **Main file path**: `app.py`
   - **App URL (Custom subdomain)**: `cyber-sentinel-soc`
5. Click **Deploy!**.

Your application will be live at:
```text
https://cyber-sentinel-soc.streamlit.app
```

---

## 🥉 Method 3: Hugging Face Spaces (100% Free, 16GB RAM)

1. Go to [Hugging Face](https://huggingface.co/) and create a **New Space**.
2. Settings:
   - **Space Name**: `cyber-sentinel`
   - **Space SDK**: **Streamlit**
   - **Space Hardware**: `CPU basic • 2 vCPU • 16GB RAM • Free`
   - **Visibility**: `Public`
3. Push using git:
   ```powershell
   git remote add space https://huggingface.co/spaces/<YOUR_HF_USERNAME>/cyber-sentinel
   git push space main
   ```
4. Hugging Face auto-builds and serves the app at:
   ```text
   https://huggingface.co/spaces/<YOUR_HF_USERNAME>/cyber-sentinel
   ```

---

## 🐳 Method 4: Deploy with Docker on Any Cloud VPS (AWS, DigitalOcean, Oracle)

If you run a Linux VM:

### 1. Clone your repository
```bash
git clone https://github.com/Ash17abd/cyber-sentinel.git
cd cyber-sentinel
```

### 2. Launch with Docker Compose
```bash
docker compose up -d --build
```
Runs on port `8501` with `restart: unless-stopped`.

---

## 🔐 Credentials for Public Reviewers

| Role | Username | Password |
| :--- | :--- | :--- |
| **Lead Administrator** | `admin` | `Admin@12345` |
| **Security Analyst** | `analyst` | `Analyst@12345` |
| **Incident Auditor** | `viewer` | `Viewer@12345` |
