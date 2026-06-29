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

username="admin"
password="admin"
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
<title>Wazuh Chat Assistant</title>
<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #1e1e1e;
        color: white;
        margin: 0;
        padding: 0;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
    }
    .chat-container {
        display: flex;
        flex-direction: column;
        height: 90vh;
        width: 600px;
        max-width: 90vw;
        border: 1px solid #3595F9;
        border-radius: 8px;
        background-color: #252931;
        box-shadow: 0 0 10px #3595F9aa;
    }
    .messages {
        flex-grow: 1;
        overflow-y: auto;
        padding: 15px;
        display: flex;
        flex-direction: column;
    }
    .message {
        max-width: 70%;
        margin: 5px 0;
        padding: 12px 16px;
        border-radius: 15px;
        word-wrap: break-word;
        white-space: pre-wrap;
        line-height: 1.4;
    }
    .message.user {
        background-color: #3595F9;
        align-self: flex-start;
        color: white;
        border-bottom-left-radius: 0;
    }
    .message.bot {
        background-color: #2c2f38;
        align-self: flex-end;
        color: #ddd;
        border-bottom-right-radius: 0;
    }
    .input-container {
        display: flex;
        padding: 10px 15px;
        background-color: #1e1e1e;
        border-top: 1px solid #3595F9;
        border-bottom-left-radius: 8px;
        border-bottom-right-radius: 8px;
    }
    input[type="text"] {
        flex-grow: 1;
        padding: 12px 15px;
        border: none;
        border-radius: 25px;
        background-color: #2c2f38;
        color: white;
        font-size: 16px;
        outline: none;
    }
    button {
        margin-left: 10px;
        padding: 12px 20px;
        background-color: #3595F9;
        border: none;
        border-radius: 25px;
        color: white;
        font-weight: bold;
        font-size: 16px;
        cursor: pointer;
        transition: background-color 0.2s ease-in-out;
    }
    button:hover {
        background-color: #1c6dd0;
    }
</style>
</head>
<body>
<div class="chat-container">
    <div class="messages" id="messages"></div>
    <div class="input-container">
        <input type="text" id="user-input" placeholder="Type your message or /help to print the help menu..." autocomplete="off" />
        <button onclick="sendMessage()">Send</button>
    </div>
</div>

<script>
    const messagesDiv = document.getElementById('messages');
    const userInput = document.getElementById('user-input');

    const socket = new WebSocket(`ws://${window.location.host}/ws/chat`);

    socket.onopen = () => {
        console.log("✅ WebSocket connected");
    };

    socket.onmessage = function(event) {
        const data = JSON.parse(event.data);
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', data.role);
        messageDiv.textContent = data.message;
        messagesDiv.appendChild(messageDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    };

    socket.onclose = () => {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', 'bot');
        messageDiv.textContent = '⚠️ Connection closed.';
        messagesDiv.appendChild(messageDiv);
    };

    socket.onerror = (error) => {
        console.error("WebSocket error:", error);
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', 'bot');
        messageDiv.textContent = '⚠️ WebSocket error.';
        messagesDiv.appendChild(messageDiv);
    };

    function sendMessage() {
        const message = userInput.value.trim();
        if (message && socket.readyState === WebSocket.OPEN) {
            // Display user message
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('message', 'user');
            messageDiv.textContent = message;
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;

            socket.send(message);
            userInput.value = '';
            userInput.focus();
        }
    }

    userInput.addEventListener("keyup", function(event) {
        if (event.key === "Enter") {
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
