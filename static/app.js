// --- State ---
let ws = null;
let isProcessing = false;
let currentAssistantEl = null;
let currentThinkingEl = null;
let currentTextEl = null;
let textAccumulator = '';
let autoScroll = true;

// --- Markdown Setup ---
if (typeof marked !== 'undefined') {
    marked.setOptions({
        highlight: function(code, lang) {
            if (typeof hljs !== 'undefined' && lang && hljs.getLanguage(lang)) {
                return hljs.highlight(code, { language: lang }).value;
            }
            return code;
        },
        breaks: true
    });
}

// --- Auth ---
function authenticate() {
    const pwd = document.getElementById('auth-password').value;
    if (!pwd) return;

    const wsUrl = `ws://${location.host}/ws`;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'auth', password: pwd }));
    };

    ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'auth_ok') {
            document.getElementById('auth-overlay').classList.add('hidden');
            document.getElementById('app').classList.remove('hidden');
            sessionStorage.setItem('ra_pwd', pwd);
            setupWsHandlers();
            loadModels();
            loadSkills();
            loadMcpServers();
            loadHistoryDates();
        } else if (msg.type === 'auth_fail') {
            const card = document.querySelector('.auth-card');
            card.classList.add('shake');
            setTimeout(() => card.classList.remove('shake'), 400);
            document.getElementById('auth-error').textContent = msg.message || 'Authentication failed';
        }
    };

    ws.onerror = () => {
        document.getElementById('auth-error').textContent = 'Connection failed';
    };
}

// Auto-auth from session
window.addEventListener('load', () => {
    const pwd = sessionStorage.getItem('ra_pwd');
    if (pwd) {
        document.getElementById('auth-password').value = pwd;
        authenticate();
    }
    // Auto-resize textarea
    const input = document.getElementById('input');
    input.addEventListener('input', () => {
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 120) + 'px';
    });
});

// --- WebSocket Handlers ---
function setupWsHandlers() {
    ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        handleServerEvent(msg);
    };
    ws.onclose = () => {
        console.log('WebSocket closed');
        // Could attempt reconnect here
    };
}

function handleServerEvent(msg) {
    switch (msg.type) {
        case 'thinking':
            hideTyping();
            ensureAssistantMsg();
            if (!currentThinkingEl) {
                currentThinkingEl = createThinkingBlock();
                currentAssistantEl.appendChild(currentThinkingEl);
            }
            currentThinkingEl.querySelector('.thinking-text').textContent += msg.content;
            currentThinkingEl.classList.add('active');
            scrollToBottom();
            break;

        case 'text':
            hideTyping();
            ensureAssistantMsg();
            finalizeThinking();
            if (!currentTextEl) {
                currentTextEl = document.createElement('div');
                currentTextEl.className = 'text-content';
                currentAssistantEl.appendChild(currentTextEl);
                textAccumulator = '';
            }
            textAccumulator += msg.content;
            currentTextEl.innerHTML = renderMarkdown(textAccumulator);
            addCopyButtons(currentTextEl);
            scrollToBottom();
            break;

        case 'tool_call':
            hideTyping();
            ensureAssistantMsg();
            finalizeThinking();
            const toolBlock = createToolBlock(msg.name, msg.call_id, msg.args);
            toolBlock.dataset.callId = msg.call_id;
            currentAssistantEl.appendChild(toolBlock);
            scrollToBottom();
            break;

        case 'tool_result':
            const block = currentAssistantEl?.querySelector(`[data-call-id="${msg.call_id}"]`);
            if (block) {
                updateToolBlock(block, msg.result);
            }
            scrollToBottom();
            break;

        case 'error':
            hideTyping();
            ensureAssistantMsg();
            const errBlock = document.createElement('div');
            errBlock.className = 'error-block';
            errBlock.textContent = '\u26A0 ' + msg.message;
            currentAssistantEl.appendChild(errBlock);
            scrollToBottom();
            break;

        case 'done':
            hideTyping();
            finalizeThinking();
            finalizeAssistantMsg();
            isProcessing = false;
            document.getElementById('send-btn').disabled = false;
            break;

        case 'cleared':
            document.getElementById('messages').innerHTML = '';
            resetAssistant();
            break;
    }
}

// --- UI Helpers ---
function ensureAssistantMsg() {
    if (!currentAssistantEl) {
        currentAssistantEl = document.createElement('div');
        currentAssistantEl.className = 'msg-assistant';
        document.getElementById('messages').appendChild(currentAssistantEl);
    }
}

function finalizeAssistantMsg() {
    if (currentAssistantEl) {
        const ts = document.createElement('div');
        ts.className = 'msg-timestamp';
        ts.textContent = new Date().toLocaleTimeString();
        currentAssistantEl.appendChild(ts);
    }
    resetAssistant();
}

function resetAssistant() {
    currentAssistantEl = null;
    currentThinkingEl = null;
    currentTextEl = null;
    textAccumulator = '';
}

function finalizeThinking() {
    if (currentThinkingEl) {
        currentThinkingEl.classList.remove('active');
        currentThinkingEl = null;
    }
}

function createThinkingBlock() {
    const div = document.createElement('div');
    div.className = 'thinking-block active';
    div.innerHTML = `
        <div class="thinking-header" onclick="toggleBlock(this)">
            <div class="thinking-label">
                <div class="thinking-spinner"></div>
                Thinking...
            </div>
            <span class="thinking-toggle">&#9660;</span>
        </div>
        <div class="thinking-content">
            <div class="thinking-text"></div>
        </div>
    `;
    return div;
}

function createToolBlock(name, callId, args) {
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args);
    const preview = argsStr.length > 60 ? argsStr.substring(0, 60) + '...' : argsStr;
    const div = document.createElement('div');
    div.className = 'tool-block active';
    div.innerHTML = `
        <div class="tool-header" onclick="toggleBlock(this)">
            <div class="tool-label">
                <span class="tool-gear">&#9881;</span>
                ${escapeHtml(name)}
            </div>
            <span class="tool-args-preview">${escapeHtml(preview)}</span>
            <span class="tool-toggle">&#9660;</span>
        </div>
        <div class="tool-detail">
            <div class="tool-detail-section">
                <div class="tool-detail-label">Arguments</div>
                <pre>${escapeHtml(JSON.stringify(args, null, 2))}</pre>
            </div>
            <div class="tool-detail-section tool-result-section" style="display:none">
                <div class="tool-detail-label">Result</div>
                <pre class="tool-result-content"></pre>
            </div>
        </div>
    `;
    return div;
}

function updateToolBlock(block, result) {
    block.classList.remove('active');
    const resultSection = block.querySelector('.tool-result-section');
    if (resultSection) {
        resultSection.style.display = 'block';
        const resultStr = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
        resultSection.querySelector('.tool-result-content').textContent = resultStr;
    }
}

function toggleBlock(header) {
    const parent = header.parentElement;
    const content = parent.querySelector('.thinking-content, .tool-detail');
    const toggle = header.querySelector('.thinking-toggle, .tool-toggle');
    if (content) {
        content.classList.toggle('expanded');
        if (toggle) {
            toggle.innerHTML = content.classList.contains('expanded') ? '&#9650;' : '&#9660;';
        }
    }
}

function renderMarkdown(text) {
    if (typeof marked !== 'undefined') {
        return marked.parse(text);
    }
    return escapeHtml(text).replace(/\n/g, '<br>');
}

function addCopyButtons(container) {
    container.querySelectorAll('pre').forEach(pre => {
        if (pre.querySelector('.copy-btn')) return;
        const btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.textContent = 'Copy';
        btn.onclick = () => {
            const code = pre.querySelector('code')?.textContent || pre.textContent;
            navigator.clipboard.writeText(code).then(() => {
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = 'Copy', 1500);
            });
        };
        pre.style.position = 'relative';
        pre.appendChild(btn);
    });
}

function showTyping() {
    document.getElementById('typing-indicator').classList.remove('hidden');
}
function hideTyping() {
    document.getElementById('typing-indicator').classList.add('hidden');
}

function scrollToBottom() {
    if (!autoScroll) return;
    const chat = document.getElementById('chat-area');
    chat.scrollTop = chat.scrollHeight;
}

// Smart auto-scroll
document.addEventListener('DOMContentLoaded', () => {
    const chat = document.getElementById('chat-area');
    if (chat) {
        chat.addEventListener('scroll', () => {
            const threshold = 80;
            autoScroll = (chat.scrollHeight - chat.scrollTop - chat.clientHeight) < threshold;
        });
    }
});

// --- Message Sending ---
function sendMessage() {
    const input = document.getElementById('input');
    const content = input.value.trim();
    if (!content || !ws || isProcessing) return;

    const model = document.getElementById('model-select').value;

    // Add user message to UI
    const userEl = document.createElement('div');
    userEl.className = 'msg-user';
    userEl.innerHTML = `<div class="text-content">${escapeHtml(content)}</div>
        <div class="msg-timestamp">${new Date().toLocaleTimeString()}</div>`;
    document.getElementById('messages').appendChild(userEl);

    input.value = '';
    input.style.height = 'auto';

    // Send to server
    ws.send(JSON.stringify({ type: 'chat', content, model }));

    isProcessing = true;
    document.getElementById('send-btn').disabled = true;
    resetAssistant();
    showTyping();
    scrollToBottom();
}

function handleKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
}

function clearChat() {
    if (ws) ws.send(JSON.stringify({ type: 'clear' }));
    document.getElementById('messages').innerHTML = '';
    resetAssistant();
}

// --- Sidebar ---
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('collapsed');
}

async function loadModels() {
    try {
        const res = await fetch('/api/models');
        const data = await res.json();
        const select = document.getElementById('model-select');
        select.innerHTML = '';
        (data.models || []).forEach(m => {
            const opt = document.createElement('option');
            opt.value = m;
            opt.textContent = m;
            select.appendChild(opt);
        });
    } catch (e) { console.error('Load models error:', e); }
}

async function loadSkills() {
    try {
        const res = await fetch('/api/skills');
        const data = await res.json();
        const list = document.getElementById('skills-list');
        list.innerHTML = '';
        (data.skills || []).forEach(s => {
            const div = document.createElement('div');
            div.className = 'sidebar-item';
            div.innerHTML = `<div class="item-name">${escapeHtml(s.name)}</div>
                <div class="item-desc">${escapeHtml(s.description)}</div>`;
            list.appendChild(div);
        });
        if (!data.skills?.length) {
            list.innerHTML = '<div class="sidebar-item">No skills installed</div>';
        }
    } catch (e) { console.error('Load skills error:', e); }
}

async function reloadSkills() {
    await fetch('/api/skills/reload', { method: 'POST' });
    loadSkills();
}

async function loadMcpServers() {
    try {
        const res = await fetch('/api/mcp');
        const data = await res.json();
        const list = document.getElementById('mcp-list');
        list.innerHTML = '';
        (data.servers || []).forEach(s => {
            const div = document.createElement('div');
            div.className = 'sidebar-item';
            const tools = (s.tools || []).map(t => t.name).join(', ');
            div.innerHTML = `<div class="item-name">${escapeHtml(s.name)}</div>
                <div class="item-desc">${escapeHtml(tools || 'No tools')}</div>`;
            list.appendChild(div);
        });
        if (!data.servers?.length) {
            list.innerHTML = '<div class="sidebar-item">No MCP servers</div>';
        }
    } catch (e) { console.error('Load MCP error:', e); }
}

async function loadHistoryDates() {
    try {
        const res = await fetch('/api/logs/dates');
        const data = await res.json();
        const list = document.getElementById('history-dates');
        list.innerHTML = '';
        (data.dates || []).sort().reverse().forEach(d => {
            const div = document.createElement('div');
            div.className = 'sidebar-item';
            div.style.cursor = 'pointer';
            div.textContent = d;
            div.onclick = () => loadHistory(d);
            list.appendChild(div);
        });
        if (!data.dates?.length) {
            list.innerHTML = '<div class="sidebar-item">No history yet</div>';
        }
    } catch (e) { console.error('Load history dates error:', e); }
}

async function loadHistory(date) {
    try {
        const res = await fetch(`/api/logs?date=${date}`);
        const data = await res.json();
        const msgs = document.getElementById('messages');
        msgs.innerHTML = `<div style="text-align:center;color:var(--text-muted);padding:12px;">History: ${date}</div>`;

        (data.entries || []).forEach(entry => {
            if (entry.role === 'user') {
                const el = document.createElement('div');
                el.className = 'msg-user';
                el.innerHTML = `<div class="text-content">${escapeHtml(entry.content || '')}</div>`;
                msgs.appendChild(el);
            } else if (entry.role === 'assistant' && entry.type === 'text') {
                const el = document.createElement('div');
                el.className = 'msg-assistant';
                el.innerHTML = `<div class="text-content">${renderMarkdown(entry.content || '')}</div>`;
                addCopyButtons(el);
                msgs.appendChild(el);
            }
        });
        scrollToBottom();
    } catch (e) { console.error('Load history error:', e); }
}

// --- Utils ---
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
