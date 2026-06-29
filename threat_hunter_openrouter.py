import json
import os
import gzip 
from datetime import datetime, timedelta
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain.schema.messages import SystemMessage, HumanMessage, AIMessage
import uvicorn
import argparse
import sys
from fastapi import Depends, status, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

app = FastAPI()
security = HTTPBasic()

class Prompt(BaseModel):
    question: str

# ===== Globals for caching =====
qa_chain = None
context = None
days_range = 7

username="<USERNAME>"
password="<PASSWORD>"
ssh_username = "<SSH_USERNAME>"
ssh_password = "<SSH_PASSWORD>"
remote_host = None

# Max characters of log text to include in the LLM context (tune to your model's context window)
MAX_LOG_CHARS = int(os.getenv("MAX_LOG_CHARS", "400000"))  # ~100k tokens

# OpenRouter configuration – set these in your environment before starting the server
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
# Default to a free model; override with OPENROUTER_MODEL env var
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    username_match = secrets.compare_digest(credentials.username, username)
    password_match = secrets.compare_digest(credentials.password, password)
    if not (username_match and password_match):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def run_daemon():
    import daemon
    log_file_path = "/var/ossec/logs/threat_hunter.log"
    with daemon.DaemonContext(
        stdout=open(log_file_path, 'a+'),
        stderr=open(log_file_path, 'a+')
    ):
        uvicorn.run(app, host="0.0.0.0", port=8000)

def load_logs_from_days(past_days=7):
    if remote_host:
        return load_logs_from_remote(remote_host, ssh_username, ssh_password, past_days)

    logs = []
    today = datetime.now()
    for i in range(past_days):
        day = today - timedelta(days=i)
        year = day.year
        month_name = day.strftime("%b")
        day_num = day.strftime("%d")

        json_path = f"/var/ossec/logs/archives/{year}/{month_name}/ossec-archive-{day_num}.json"
        gz_path = f"/var/ossec/logs/archives/{year}/{month_name}/ossec-archive-{day_num}.json.gz"

        file_path = None
        open_func = None

        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            file_path = json_path
            open_func = open
        elif os.path.exists(gz_path) and os.path.getsize(gz_path) > 0:
            file_path = gz_path
            open_func = gzip.open
        else:
            print(f"⚠️ Log file missing or empty: {json_path} / {gz_path}")
            continue

        try:
            with open_func(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.strip():
                        try:
                            log = json.loads(line.strip())
                            logs.append(log)
                        except json.JSONDecodeError:
                            print(f"⚠️ Skipping invalid JSON line in {file_path}")
        except Exception as e:
            print(f"⚠️ Error reading {file_path}: {e}")
    return logs
    
def load_logs_from_remote(host, user, password, past_days):
    import paramiko
    logs = []
    today = datetime.now()

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, password=password, timeout=10)
        sftp = ssh.open_sftp()

        for i in range(past_days):
            day = today - timedelta(days=i)
            year = day.year
            month_name = day.strftime("%b")
            day_num = day.strftime("%d")
            base_path = f"/var/ossec/logs/archives/{year}/{month_name}"
            json_path = f"{base_path}/ossec-archive-{day_num}.json"
            gz_path = f"{base_path}/ossec-archive-{day_num}.json.gz"

            remote_file = None
            try:
                if sftp.stat(json_path).st_size > 0:
                    remote_file = sftp.open(json_path, 'r')
                elif sftp.stat(gz_path).st_size > 0:
                    remote_file = gzip.GzipFile(fileobj=sftp.open(gz_path, 'rb'))
            except IOError:
                print(f"⚠️ Remote log not found or unreadable: {json_path} / {gz_path}")
                continue

            if remote_file:
                try:
                    for line in remote_file:
                        if isinstance(line, bytes):
                            line = line.decode('utf-8', errors='ignore')
                        if line.strip():
                            try:
                                log = json.loads(line.strip())
                                logs.append(log)
                            except json.JSONDecodeError:
                                print(f"⚠️ Skipping invalid JSON line from remote file.")
                except Exception as e:
                    print(f"⚠️ Error reading remote file: {e}")
        sftp.close()
        ssh.close()
    except Exception as e:
        print(f"❌ Remote connection failed: {e}")
    return logs

def build_system_prompt(logs):
    header = (
        "You are a security analyst performing threat hunting.\n"
        "You have been given a set of Wazuh archive logs below. "
        "Analyze them to identify potential security threats, anomalies, or anything else the user asks about.\n"
        "All questions should be answered using the log data provided.\n\n"
        "=== WAZUH LOGS ===\n"
    )
    log_lines = []
    for log in logs:
        line = log.get('full_log') or json.dumps(log)
        log_lines.append(line)
    log_text = "\n".join(log_lines)
    if len(log_text) > MAX_LOG_CHARS:
        log_text = log_text[:MAX_LOG_CHARS] + "\n...[truncated]..."
        print(f"⚠️ Log context truncated to {MAX_LOG_CHARS} characters.")
    return header + log_text

def setup_chain(past_days=7):
    global qa_chain, context, days_range
    days_range = past_days
    print(f"🔄 Initializing QA chain with logs from past {past_days} days...")
    logs = load_logs_from_days(past_days)
    if not logs:
        print("❌ No logs found. Skipping chain setup.")
        return

    print(f"✅ {len(logs)} logs loaded from the last {past_days} days.")

    if not OPENROUTER_API_KEY:
        print("❌ OPENROUTER_API_KEY environment variable is not set.")
        return

    print("📤 Building log context for LLM (no local vectorstore needed)...")
    context = build_system_prompt(logs)
    qa_chain = ChatOpenAI(
        model=OPENROUTER_MODEL,
        openai_api_key=OPENROUTER_API_KEY,
        openai_api_base="https://openrouter.ai/api/v1",
        default_headers={
            "HTTP-Referer": "https://github.com/wazuh/threat-hunter",
            "X-Title": "Wazuh Threat Hunter",
        },
    )
    print("✅ LLM ready. Logs injected into context.")

def get_stats(logs):
    total_logs = len(logs)
    dates = [datetime.strptime(log.get('timestamp', '')[:10], "%Y-%m-%d") for log in logs if 'timestamp' in log and log.get('timestamp')]
    date_range = ""
    if dates:
        earliest = min(dates).strftime("%Y-%m-%d")
        latest = max(dates).strftime("%Y-%m-%d")
        date_range = f" from {earliest} to {latest}"
    return f"Logs loaded: {total_logs}{date_range}"

# ========= WebSocket Chat =========

chat_history = []

@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    global qa_chain, context, chat_history, days_range
    await websocket.accept()

    try:
        if not context:
            await websocket.send_json({"role": "bot", "message": "⚠️ Assistant not ready yet. Please wait."})
            await websocket.close()
            return
        
        chat_history = [SystemMessage(content=context)]
        await websocket.send_json({"role": "bot", "message": f"👋 Hello! Ask me anything about Wazuh logs.\n(Default date range is {days_range} days.)\nType /help for commands."})

        while True:
            data = await websocket.receive_text()
            if not data.strip():
                continue
            
            # Commands handling
            if data.lower() == "/help":
                help_msg = (
                    "📋 Help Menu:\n"
                    "/reload - Reload logs from Wazuh and refresh the LLM context.\n"
                    "/set days <number> - Set number of days for logs to load (1-365).\n"
                    "/stat - Show quick statistics and insights about the logs."
                )
                await websocket.send_json({"role": "bot", "message": help_msg})
                continue

            if data.lower() == "/reload":
                await websocket.send_json({"role": "bot", "message": f"🔄 Reloading logs for past {days_range} days..."})
                setup_chain(past_days=days_range)
                if qa_chain:
                    await websocket.send_json({"role": "bot", "message": f"✅ Reload complete. Now using logs from past {days_range} days."})
                    chat_history = [SystemMessage(content=context)]
                else:
                    await websocket.send_json({"role": "bot", "message": "❌ Reload failed: no logs found or error initializing chain."})
                continue

            if data.lower().startswith("/set days"):
                try:
                    parts = data.split()
                    new_days = int(parts[-1])
                    if new_days < 1 or new_days > 365:
                        await websocket.send_json({"role": "bot", "message": "⚠️ Please specify a number between 1 and 365."})
                        continue
                    days_range = new_days
                    await websocket.send_json({"role": "bot", "message": f"✅ Date range set to {days_range} days (effective on next reload)."})
                except Exception:
                    await websocket.send_json({"role": "bot", "message": "⚠️ Invalid command format. Use: /set days <number>."})
                continue

            if data.lower() == "/stat":
                logs = load_logs_from_days(days_range)
                stats = get_stats(logs)
                await websocket.send_json({"role": "bot", "message": stats})
                continue
            
            # Regular question
            chat_history.append(HumanMessage(content=data))
            print(f"🧠 Received question: {data}")

            response = qa_chain.invoke(chat_history)
            answer = response.content.replace("\\n", "\n").strip()
            if not answer:
                answer = "⚠️ Sorry, I couldn't generate a response."

            chat_history.append(AIMessage(content=answer))
            await websocket.send_json({"role": "bot", "message": answer})

    except WebSocketDisconnect:
        print("⚠️ Client disconnected.")
    except Exception as e:
        print(f"❌ Error in websocket: {e}")
        await websocket.send_json({"role": "bot", "message": f"❌ Error: {str(e)}"})
        await websocket.close()

# ======= HTML UI =======

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Wazuh Threat Hunter</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Inter', sans-serif;
    background-color: #212121;
    color: #ececec;
    height: 100dvh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* ── Top bar ── */
  .topbar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 24px;
    background: #2a2a2a;
    border-bottom: 1px solid #333;
    flex-shrink: 0;
  }
  .topbar-icon {
    width: 32px; height: 32px;
    background: #10a37f;
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px;
  }
  .topbar h1 { font-size: 15px; font-weight: 600; color: #ececec; }
  .topbar-sub { font-size: 12px; color: #8e8ea0; margin-left: auto; }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #555; margin-left: 6px; flex-shrink: 0;
    transition: background 0.3s;
  }
  .status-dot.connected { background: #10a37f; }

  /* ── Message area ── */
  #messages {
    flex: 1;
    overflow-y: auto;
    padding: 24px 0 8px;
    display: flex;
    flex-direction: column;
    gap: 0;
    scroll-behavior: smooth;
  }
  #messages::-webkit-scrollbar { width: 6px; }
  #messages::-webkit-scrollbar-track { background: transparent; }
  #messages::-webkit-scrollbar-thumb { background: #444; border-radius: 3px; }

  .row {
    display: flex;
    padding: 6px 24px;
    gap: 14px;
    align-items: flex-start;
    max-width: 860px;
    width: 100%;
    margin: 0 auto;
  }
  .row.user { flex-direction: row-reverse; }

  .avatar {
    width: 30px; height: 30px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 13px; font-weight: 600; flex-shrink: 0; margin-top: 2px;
  }
  .row.bot .avatar  { background: #10a37f; color: #fff; }
  .row.user .avatar { background: #5b5b5b; color: #fff; }

  .bubble {
    max-width: 75%;
    padding: 10px 14px;
    border-radius: 16px;
    font-size: 14px;
    line-height: 1.65;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .row.bot  .bubble { background: #2a2a2a; color: #ececec; border-top-left-radius: 4px; }
  .row.user .bubble { background: #10a37f; color: #fff;    border-top-right-radius: 4px; }

  .bubble.thinking {
    color: #8e8ea0;
    font-style: italic;
    background: transparent;
    padding-left: 0;
    animation: pulse 1.4s ease-in-out infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

  /* ── Empty state ── */
  .empty-state {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    color: #555;
    user-select: none;
  }
  .empty-state .icon { font-size: 40px; }
  .empty-state p { font-size: 14px; }

  /* ── Input area ── */
  .input-wrap {
    flex-shrink: 0;
    padding: 16px 24px 20px;
    background: #212121;
  }
  .input-box {
    max-width: 860px;
    margin: 0 auto;
    display: flex;
    align-items: flex-end;
    gap: 8px;
    background: #2a2a2a;
    border: 1px solid #444;
    border-radius: 16px;
    padding: 10px 12px 10px 16px;
    transition: border-color 0.2s;
  }
  .input-box:focus-within { border-color: #10a37f; }

  textarea {
    flex: 1;
    background: transparent;
    border: none;
    outline: none;
    color: #ececec;
    font-family: inherit;
    font-size: 14px;
    line-height: 1.5;
    resize: none;
    max-height: 160px;
    overflow-y: auto;
    padding: 2px 0;
  }
  textarea::placeholder { color: #666; }
  textarea::-webkit-scrollbar { width: 4px; }
  textarea::-webkit-scrollbar-thumb { background: #444; border-radius: 2px; }

  .send-btn {
    width: 34px; height: 34px; flex-shrink: 0;
    background: #10a37f;
    border: none; border-radius: 10px;
    color: #fff; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    transition: background 0.2s, opacity 0.2s;
  }
  .send-btn:hover { background: #0d8f6f; }
  .send-btn:disabled { background: #333; opacity: 0.5; cursor: default; }
  .send-btn svg { width: 16px; height: 16px; }

  .input-hint { text-align: center; font-size: 11px; color: #555; margin-top: 8px; max-width: 860px; margin-inline: auto; }
</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-icon">🛡️</div>
  <h1>Wazuh Threat Hunter</h1>
  <span class="topbar-sub">Powered by OpenRouter</span>
  <div class="status-dot" id="status-dot"></div>
</div>

<div id="messages">
  <div class="empty-state" id="empty-state">
    <div class="icon">🔍</div>
    <p>Ask anything about your Wazuh logs. Type <strong>/help</strong> for commands.</p>
  </div>
</div>

<div class="input-wrap">
  <div class="input-box">
    <textarea id="user-input" rows="1" placeholder="Ask about threats, anomalies, or type /help…"></textarea>
    <button class="send-btn" id="send-btn" onclick="sendMessage()" disabled title="Send">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="22" y1="2" x2="11" y2="13"></line>
        <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
      </svg>
    </button>
  </div>
  <div class="input-hint">Enter to send &nbsp;·&nbsp; Shift+Enter for new line</div>
</div>

<script>
  const messagesDiv  = document.getElementById('messages');
  const userInput    = document.getElementById('user-input');
  const sendBtn      = document.getElementById('send-btn');
  const statusDot    = document.getElementById('status-dot');
  const emptyState   = document.getElementById('empty-state');

  let awaitingReply = false;
  let thinkingRow   = null;

  // ── Auto-resize textarea ──
  userInput.addEventListener('input', () => {
    userInput.style.height = 'auto';
    userInput.style.height = Math.min(userInput.scrollHeight, 160) + 'px';
    sendBtn.disabled = !userInput.value.trim() || awaitingReply;
  });

  // ── WebSocket ──
  const socket = new WebSocket(`ws://${window.location.host}/ws/chat`);

  socket.onopen = () => {
    statusDot.classList.add('connected');
    sendBtn.disabled = !userInput.value.trim();
  };

  socket.onmessage = (event) => {
    removeThinking();
    const data = JSON.parse(event.data);
    appendMessage(data.role, data.message);
    awaitingReply = false;
    sendBtn.disabled = !userInput.value.trim();
  };

  socket.onclose = () => {
    statusDot.classList.remove('connected');
    removeThinking();
    appendMessage('bot', '⚠️ Connection closed.');
    awaitingReply = false;
    sendBtn.disabled = true;
  };

  socket.onerror = () => {
    removeThinking();
    appendMessage('bot', '⚠️ WebSocket error.');
    awaitingReply = false;
  };

  // ── Helpers ──
  function appendMessage(role, text) {
    if (emptyState) emptyState.remove();

    const row    = document.createElement('div');
    row.className = 'row ' + role;

    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    avatar.textContent = role === 'bot' ? 'W' : 'U';

    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.textContent = text;

    row.appendChild(avatar);
    row.appendChild(bubble);
    messagesDiv.appendChild(row);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    return row;
  }

  function showThinking() {
    if (emptyState) emptyState.remove();
    const row    = document.createElement('div');
    row.className = 'row bot';
    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    avatar.textContent = 'W';
    const bubble = document.createElement('div');
    bubble.className = 'bubble thinking';
    bubble.textContent = 'Analyzing logs…';
    row.appendChild(avatar);
    row.appendChild(bubble);
    messagesDiv.appendChild(row);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    thinkingRow = row;
  }

  function removeThinking() {
    if (thinkingRow) { thinkingRow.remove(); thinkingRow = null; }
  }

  function sendMessage() {
    const message = userInput.value.trim();
    if (!message || socket.readyState !== WebSocket.OPEN || awaitingReply) return;

    appendMessage('user', message);
    socket.send(message);

    userInput.value = '';
    userInput.style.height = 'auto';
    sendBtn.disabled = true;
    awaitingReply = true;
    showThinking();
    userInput.focus();
  }

  userInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def get(username: str = Depends(authenticate)):
    return HTML_PAGE


@app.on_event("startup")
def on_startup():
    print("🚀 Starting FastAPI app and loading vector store...")
    setup_chain(past_days=days_range)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--daemon", action="store_true", help="Run as daemon")
    parser.add_argument("-H", "--host", type=str, help="Optional remote host IP address to load logs from")
    args = parser.parse_args()

    if args.host:
        remote_host = args.host

    if args.daemon:
        run_daemon()
    else:
        uvicorn.run(app, host="0.0.0.0", port=8000)