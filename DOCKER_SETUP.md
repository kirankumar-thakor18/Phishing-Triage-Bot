# Docker Setup Guide (Windows 11, AMD64)

Ye guide is project ko Docker se chalane ke liye hai. Reboot ke baad isi file
ko follow karo — chat ki zaroorat nahi.

Project ka current status: code GitHub pe pushed hai, Docker files ready hain
(`Dockerfile`, `.dockerignore`, `docker-compose.yml`).

---

## 0. Prerequisites

- Windows 11 (Pro/Home) — AMD64 / x64
- Virtualization BIOS mein ON (Task Manager -> Performance -> CPU -> "Virtualization: Enabled")
- Internet connection

---

## 1. WSL2 install karo (ek baar)

PowerShell **as Administrator** kholo aur:

```powershell
wsl --install
```

Phir **reboot** karo.

Verify (reboot ke baad):

```powershell
wsl --status
wsl -l -v
```

`Ubuntu` (ya koi distro) aur `VERSION 2` dikhna chahiye.

---

## 2. Docker Desktop install karo

Download (AMD64 version): https://www.docker.com/products/docker-desktop/

- Installer chalao.
- Install ke waqt **"Use WSL 2 instead of Hyper-V"** checked rakho (recommended).
- Agar reboot maange to reboot karo.
- Docker Desktop kholo aur sign-in / accept karo.

---

## 3. Install verify karo

```powershell
docker --version
docker run hello-world
```

`Hello from Docker!` aana chahiye. Agar aa gaya to setup done.

---

## 4. Project run karo

```powershell
cd C:\Users\HP\Desktop\phishing-triage-bot
docker compose up --build
```

Browser mein kholo: http://127.0.0.1:5000

Stop karne ke liye terminal mein `Ctrl + C`, phir:

```powershell
docker compose down
```

> `.env` file project folder mein honi chahiye (API keys). Compose use automatically load karta hai.

---

## 5. Docker commands (reference)

```powershell
# image build
docker build -t phishing-bot .

# container run (history volume ke saath)
docker run -p 5000:5000 --env-file .env -e SCANS_DB=/app/data/scans.db -v phishing_data:/app/data phishing-bot

# compose se run
docker compose up --build

# background mein run
docker compose up -d --build

# logs dekho
docker compose logs -f

# band karo
docker compose down

# images list
docker images

# image delete
docker rmi phishing-bot
```

---

## 6. Troubleshooting

| Problem | Fix |
|---|---|
| `docker: command not found` | Docker Desktop install/start nahi hua; restart Docker Desktop |
| `WSL 2 installation is incomplete` | `wsl --update` chalao, phir Docker Desktop restart |
| `port is already allocated` (5000) | purana container band karo: `docker compose down`, ya port badlo `-p 5001:5000` |
| Build slow / fails on pip | internet check karo; `docker compose build --no-cache` try karo |
| History restart pe gayab | volume check karo: `docker volume ls` |
| Virtualization disabled | BIOS mein VT-x / AMD-V (SVM) enable karo |

---

## 7. Security notes

- `.env` (API keys) kabhi commit mat karo — `.gitignore` mein already hai.
- Keys image ke andar nahi jaati; runtime pe `--env-file .env` se pass hoti hain.
- Container non-root user (`appuser`) ke roop mein chalta hai.
- Public deployment pe disclaimer rakho: demo tool, real sensitive emails upload na karo.

---

## 8. Reboot ke baad quick checklist

```powershell
docker --version
docker run hello-world
cd C:\Users\HP\Desktop\phishing-triage-bot
docker compose up --build
# http://127.0.0.1:5000
```
