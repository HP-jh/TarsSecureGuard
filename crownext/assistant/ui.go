package assistant

const assistantUIHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TSG Assistant</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f6f7; color: #1f2329; height: 100vh; display: flex; flex-direction: column; }
header { background: #3370ff; color: #fff; padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; }
header h1 { font-size: 16px; font-weight: 600; }
header .meta { font-size: 12px; opacity: 0.85; }
main { flex: 1; display: flex; overflow: hidden; }
.sidebar { width: 260px; background: #fff; border-right: 1px solid #dee0e3; display: flex; flex-direction: column; }
.sidebar h2 { font-size: 13px; padding: 12px 16px; color: #646a73; border-bottom: 1px solid #dee0e3; }
.session-list { flex: 1; overflow-y: auto; padding: 8px; }
.session-item { padding: 10px 12px; border-radius: 6px; cursor: pointer; margin-bottom: 4px; font-size: 13px; }
.session-item:hover, .session-item.active { background: #f2f3f5; }
.session-item .time { font-size: 11px; color: #8f959e; }
.chat-area { flex: 1; display: flex; flex-direction: column; background: #fff; }
.messages { flex: 1; overflow-y: auto; padding: 20px; }
.message { max-width: 80%; margin-bottom: 16px; padding: 12px 16px; border-radius: 8px; font-size: 14px; line-height: 1.6; }
.message.user { background: #3370ff; color: #fff; margin-left: auto; }
.message.assistant { background: #f2f3f5; color: #1f2329; }
.message.tool { background: #fff7e6; color: #8c6c1d; font-size: 12px; }
.input-area { padding: 12px 20px; border-top: 1px solid #dee0e3; display: flex; gap: 8px; align-items: flex-end; }
.input-area textarea { flex: 1; border: 1px solid #dee0e3; border-radius: 8px; padding: 10px 14px; font-size: 14px; resize: none; height: 48px; max-height: 120px; }
.input-area button { padding: 10px 20px; background: #3370ff; color: #fff; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; }
.input-area button:hover { background: #2860d8; }
.toolbar { display: flex; gap: 8px; padding: 8px 20px; border-top: 1px solid #dee0e3; background: #fafbfc; }
.toolbar select { padding: 6px 10px; border: 1px solid #dee0e3; border-radius: 6px; font-size: 13px; }
.toolbar label { font-size: 12px; color: #646a73; display: flex; align-items: center; gap: 4px; }
.tool-badge { display: inline-block; padding: 2px 8px; background: #e1eaff; color: #3370ff; border-radius: 4px; font-size: 11px; margin-right: 4px; }
.confirm-box { background: #fff2f0; border: 1px solid #ffccc7; padding: 12px; border-radius: 8px; margin: 8px 0; }
.confirm-box button { padding: 6px 14px; border: none; border-radius: 6px; cursor: pointer; margin-right: 8px; }
.confirm-box .yes { background: #ff4d4f; color: #fff; }
.confirm-box .no { background: #fff; border: 1px solid #d9d9d9; }
.empty-state { text-align: center; padding: 60px 20px; color: #8f959e; }
.empty-state h3 { font-size: 16px; margin-bottom: 8px; color: #646a73; }
</style>
</head>
<body>
<header>
  <h1>TSG 智能助手</h1>
  <div class="meta">v4.1.0 · 网关助手</div>
</header>
<main>
  <aside class="sidebar">
    <h2>会话历史</h2>
    <div class="session-list" id="sessionList"></div>
    <div style="padding: 12px; border-top: 1px solid #dee0e3;">
      <button onclick="newSession()" style="width:100%;padding:8px;background:#3370ff;color:#fff;border:none;border-radius:6px;cursor:pointer;">新建会话</button>
    </div>
  </aside>
  <section class="chat-area">
    <div class="messages" id="messages">
      <div class="empty-state">
        <h3>欢迎使用 TSG 智能助手</h3>
        <p>支持模型自动/手动选择、工具调用、多步交互</p>
      </div>
    </div>
    <div class="toolbar">
      <label>模式
        <select id="modeSelect" onchange="setMode()">
          <option value="auto">自动选择</option>
          <option value="manual">手动指定</option>
        </select>
      </label>
      <label>模型
        <select id="providerSelect" disabled>
          <option>加载中...</option>
        </select>
      </label>
      <label>角色
        <select id="roleSelect">
          <option value="user">用户</option>
          <option value="admin">管理员</option>
        </select>
      </label>
      <span id="toolCount" style="margin-left:auto;font-size:12px;color:#646a73;"></span>
    </div>
    <div class="input-area">
      <textarea id="inputBox" placeholder="输入消息..." onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();send();}"></textarea>
      <button onclick="send()">发送</button>
    </div>
  </section>
</main>
<script>
let sessionId = '';
let providers = [];
let tools = [];

async function init() {
  await Promise.all([loadProviders(), loadTools()]);
  await loadSessions();
}

async function loadProviders() {
  const r = await fetch('/api/assistant/providers');
  providers = await r.json();
  const sel = document.getElementById('providerSelect');
  sel.innerHTML = providers.map(p => '<option value="' + p.name + '">' + p.name + ' (' + (p.healthy ? '健康' : '异常') + ')</option>').join('');
}

async function loadTools() {
  const r = await fetch('/api/assistant/tools');
  tools = await r.json();
  document.getElementById('toolCount').textContent = tools.length + ' 个工具可用';
}

async function loadSessions() {
  const r = await fetch('/api/assistant/sessions');
  const list = await r.json();
  const container = document.getElementById('sessionList');
  container.innerHTML = list.map(s => '<div class="session-item" data-id="' + s.id + '" onclick="switchSession(this)">' +
    '<div>' + (s.messages.length ? s.messages[s.messages.length-1].content.substring(0, 30) : '新会话') + '</div>' +
    '<div class="time">' + new Date(s.updated_at).toLocaleString() + '</div></div>').join('');
}

function switchSession(el) {
  document.querySelectorAll('.session-item').forEach(e => e.classList.remove('active'));
  el.classList.add('active');
  sessionId = el.dataset.id;
  loadSession(sessionId);
}

async function loadSession(id) {
  const r = await fetch('/api/assistant/sessions/' + id);
  const s = await r.json();
  const box = document.getElementById('messages');
  box.innerHTML = '';
  for (const m of s.messages) {
    appendMessage(m.role, m.content);
  }
  document.getElementById('modeSelect').value = s.mode;
  setMode();
  if (s.provider) document.getElementById('providerSelect').value = s.provider;
}

async function newSession() {
  const r = await fetch('/api/assistant/sessions', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({user_id:'user', role: document.getElementById('roleSelect').value}) });
  const s = await r.json();
  sessionId = s.id;
  await loadSessions();
  document.getElementById('messages').innerHTML = '<div class="empty-state"><h3>新会话已开始</h3><p>发送消息开始对话</p></div>';
}

function setMode() {
  const manual = document.getElementById('modeSelect').value === 'manual';
  document.getElementById('providerSelect').disabled = !manual;
}

function appendMessage(role, content) {
  const box = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = 'message ' + role;
  div.textContent = content;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

async function send() {
  const box = document.getElementById('inputBox');
  const text = box.value.trim();
  if (!text) return;
  if (!sessionId) { await newSession(); }
  appendMessage('user', text);
  box.value = '';

  const payload = {
    session_id: sessionId,
    message: text,
    mode: document.getElementById('modeSelect').value,
    provider: document.getElementById('providerSelect').value,
    role: document.getElementById('roleSelect').value
  };
  const r = await fetch('/api/assistant/chat', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const data = await r.json();
  if (data.error) {
    appendMessage('assistant', '错误: ' + data.error);
  } else {
    appendMessage('assistant', data.response + ' [via ' + data.provider + '/' + data.model + ']');
  }
}

init();
</script>
</body>
</html>`
