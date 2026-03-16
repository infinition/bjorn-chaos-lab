/**
 * Bjorn Chaos Lab -- Frontend Application
 * Vanilla JS, zero dependencies.
 * Connects to lab_server.py REST API + SSE.
 */

(() => {
    'use strict';

    // ==========================================================================
    // DOM helpers
    // ==========================================================================
    const $ = (sel, root = document) => root.querySelector(sel);
    const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
    const el = (tag, attrs = {}, children = []) => {
        const e = document.createElement(tag);
        for (const [k, v] of Object.entries(attrs)) {
            if (k === 'onclick' || k === 'oninput') e[k] = v;
            else if (k === 'textContent') e.textContent = v;
            else if (k === 'innerHTML') e.innerHTML = v;
            else e.setAttribute(k, v);
        }
        for (const c of children) {
            if (typeof c === 'string') e.appendChild(document.createTextNode(c));
            else if (c) e.appendChild(c);
        }
        return e;
    };

    // ==========================================================================
    // State
    // ==========================================================================
    let connected = false;
    let deploying = false;
    let eventSource = null;
    let pollTimer = null;
    let cachedTargets = [];
    let lastTargetsJSON = '';

    // ==========================================================================
    // API helpers
    // ==========================================================================
    async function api(method, path, body = null) {
        const opts = { method, headers: {} };
        if (body) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(path, opts);
        return res.json();
    }

    // ==========================================================================
    // Toast
    // ==========================================================================
    function toast(msg, level = 'info', ms = 3000) {
        const container = $('#toastContainer');
        const d = el('div', { class: `toast ${level}` }, [msg]);
        container.appendChild(d);
        setTimeout(() => { d.style.opacity = '0'; setTimeout(() => d.remove(), 300); }, ms);
    }

    // ==========================================================================
    // Clipboard / Download
    // ==========================================================================
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(
            () => toast('Copied!', 'success', 1500),
            () => toast('Copy failed', 'error')
        );
    }

    function downloadFile(filename, content) {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ==========================================================================
    // Collect users / passwords from cached targets
    // ==========================================================================
    function collectUsers() {
        const users = new Set();
        for (const t of cachedTargets) {
            if (t.system && t.system.user) users.add(t.system.user);
            users.add('root');
            if (t.services) {
                for (const svc of t.services) {
                    if (svc.creds) {
                        const u = svc.creds.split(':')[0];
                        if (u) users.add(u);
                    }
                }
            }
        }
        return [...users];
    }

    function collectPasswords() {
        const passwords = new Set();
        for (const t of cachedTargets) {
            if (t.system && t.system.password) passwords.add(t.system.password);
            if (t.root_password) passwords.add(t.root_password);
            if (t.services) {
                for (const svc of t.services) {
                    if (svc.creds) {
                        const parts = svc.creds.split(':');
                        if (parts.length >= 2) passwords.add(parts.slice(1).join(':'));
                    }
                }
            }
        }
        return [...passwords];
    }

    // ==========================================================================
    // Status Indicator
    // ==========================================================================
    function setConnected(val, host = '') {
        connected = val;
        const dot = $('.status-dot');
        const txt = $('.status-text');
        if (val) {
            dot.classList.add('connected');
            txt.textContent = `Connected -- ${host}`;
            // Hide connect panel, show everything else
            $('#connectPanel').style.display = 'none';
            $('#btnDisconnect').style.display = '';
            $('#deployPanel').style.display = '';
            $('#targetsPanel').style.display = '';
            $('#validatePanel').style.display = '';
            $('#credsPanel').style.display = '';
            $('#consolePanel').style.display = '';

            // Mobile tabs: show tab bar and activate first tab
            if (mobileMode) {
                $('#mobileTabBar').classList.add('visible');
                switchTab(activeTab);
            }
        } else {
            dot.classList.remove('connected');
            txt.textContent = 'Disconnected';
            // Show connect panel, hide everything else
            $('#connectPanel').style.display = '';
            $('#btnDisconnect').style.display = 'none';
            $('#deployPanel').style.display = 'none';
            $('#targetsPanel').style.display = 'none';
            $('#validatePanel').style.display = 'none';
            $('#credsPanel').style.display = 'none';
            $('#consolePanel').style.display = 'none';
            $('#mobileTabBar').classList.remove('visible');
        }
    }

    // ==========================================================================
    // SSE
    // ==========================================================================
    function startSSE() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/api/events');
        eventSource.onmessage = (ev) => {
            try {
                const data = JSON.parse(ev.data);
                appendConsole(data.level, data.message, data.ts);
            } catch (e) { }
        };
        eventSource.onerror = () => { };
    }

    function appendConsole(level, message, ts) {
        const output = $('#consoleOutput');
        const time = ts ? new Date(ts * 1000).toLocaleTimeString() : new Date().toLocaleTimeString();

        const line = el('div', { class: 'console-line' }, [
            el('span', { class: 'console-ts', textContent: time }),
            el('span', { class: `console-level ${level}`, textContent: level }),
            el('span', { class: 'console-msg', textContent: message }),
        ]);
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;

        while (output.children.length > 500) {
            output.removeChild(output.firstChild);
        }
    }

    // ==========================================================================
    // Connect
    // ==========================================================================
    async function handleConnect() {
        const host = $('#inputHost').value.trim();
        const user = $('#inputUser').value.trim();
        const password = $('#inputPassword').value.trim();
        const network = $('#inputNetwork').value.trim();

        if (!host || !user || !password) {
            toast('All fields are required', 'warn');
            return;
        }

        const btn = $('#btnConnect');
        btn.disabled = true;
        btn.textContent = 'Connecting...';

        try {
            const res = await api('POST', '/api/connect', { host, user, password, network });
            if (res.error) {
                toast(`Error: ${res.error}`, 'error');
                btn.textContent = 'Connect';
                btn.disabled = false;
                return;
            }

            setConnected(true, host);
            startSSE();
            startPolling();

            if (!res.image_exists) {
                toast('Docker image "bjorn-victim" not found. Build it first.', 'warn', 6000);
            } else {
                toast('Connected to Docker host', 'success');
            }
        } catch (e) {
            toast(`Network error: ${e.message}`, 'error');
        }

        btn.textContent = 'Connect';
        btn.disabled = false;
    }

    // ==========================================================================
    // Disconnect
    // ==========================================================================
    function handleDisconnect() {
        if (eventSource) { eventSource.close(); eventSource = null; }
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        cachedTargets = [];
        lastTargetsJSON = '';
        setConnected(false);
        toast('Disconnected', 'info');
    }

    // ==========================================================================
    // Deploy
    // ==========================================================================
    async function handleDeploy() {
        if (deploying) return;
        deploying = true;

        const count = parseInt($('#inputCount').value) || 1;
        const mode = $('#selectMode').value;
        const difficulty = $('#selectDifficulty').value;

        const btn = $('#btnDeploy');
        btn.disabled = true;
        btn.textContent = 'Deploying...';

        try {
            await api('POST', '/api/deploy', { count, mode, difficulty });
            toast(`Deploying ${count} target(s) [${difficulty}]`, 'success');
        } catch (e) {
            toast(`Error: ${e.message}`, 'error');
        }

        setTimeout(() => {
            btn.disabled = false;
            btn.textContent = 'Deploy';
            deploying = false;
        }, 3000);
    }

    // ==========================================================================
    // Clean All
    // ==========================================================================
    async function handleCleanAll() {
        if (!confirm('Delete ALL target-* containers? This is irreversible.')) return;

        const btn = $('#btnCleanAll');
        btn.disabled = true;

        try {
            await api('POST', '/api/clean');
            toast('Cleaning up...', 'info');
        } catch (e) {
            toast(`Error: ${e.message}`, 'error');
        }

        setTimeout(() => { btn.disabled = false; }, 2000);
    }

    // ==========================================================================
    // Delete Single
    // ==========================================================================
    async function handleDelete(hostname) {
        if (!confirm(`Delete ${hostname}?`)) return;

        try {
            await api('POST', '/api/delete', { hostname });
            toast(`${hostname} deleted`, 'success');
            refreshTargets();
        } catch (e) {
            toast(`Error: ${e.message}`, 'error');
        }
    }

    // ==========================================================================
    // Flag Validation
    // ==========================================================================
    async function handleValidate() {
        const flag = $('#inputFlag').value.trim();
        if (!flag) {
            toast('Enter a flag to validate', 'warn');
            return;
        }

        const resultDiv = $('#validateResult');
        try {
            const res = await api('POST', '/api/validate', { flag });
            if (res.valid) {
                resultDiv.className = 'validate-result valid';
                resultDiv.textContent = `Valid flag! Host: ${res.hostname} | Location: ${res.location}`;
                toast('Flag accepted!', 'success');
            } else {
                resultDiv.className = 'validate-result invalid';
                resultDiv.textContent = 'Invalid flag. Try again.';
            }
        } catch (e) {
            resultDiv.className = 'validate-result invalid';
            resultDiv.textContent = `Error: ${e.message}`;
        }
    }

    // ==========================================================================
    // Credential Upload
    // ==========================================================================
    async function handleUploadCreds() {
        const ssh_host = $('#credsHost').value.trim();
        const ssh_user = $('#credsUser').value.trim();
        const ssh_pass = $('#credsPass').value.trim();
        const remote_path = $('#credsPath').value.trim();

        if (!ssh_host || !ssh_user || !ssh_pass) {
            toast('SSH host, user, and password required', 'warn');
            return;
        }

        const btn = $('#btnUploadCreds');
        btn.disabled = true;
        btn.textContent = 'Uploading...';

        try {
            await api('POST', '/api/upload-creds', { ssh_host, ssh_user, ssh_pass, remote_path });
            toast('Credential upload started. Check console for status.', 'success');
        } catch (e) {
            toast(`Error: ${e.message}`, 'error');
        }

        setTimeout(() => {
            btn.disabled = false;
            btn.textContent = 'Upload Credentials';
        }, 3000);
    }

    // ==========================================================================
    // Targets rendering (stable, no flicker)
    // ==========================================================================
    function renderTargets(targets) {
        const newJSON = JSON.stringify(targets);
        if (newJSON === lastTargetsJSON) return;
        lastTargetsJSON = newJSON;
        cachedTargets = targets;

        const container = $('#targetsContainer');
        if (!container) return;

        const countEl = $('#targetCount');
        if (countEl) countEl.textContent = targets.length;

        if (targets.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No targets deployed.</p></div>';
            return;
        }

        // Preserve expanded state
        const expanded = new Set();
        $$('.target-card.expanded', container).forEach(c => expanded.add(c.dataset.name));

        container.innerHTML = '';

        for (const tgt of targets) {
            const card = el('div', {
                class: `target-card${expanded.has(tgt.hostname) ? ' expanded' : ''}`,
                'data-name': tgt.hostname,
            });

            const diffClass = tgt.difficulty || 'medium';

            const header = el('div', { class: 'target-header', onclick: () => card.classList.toggle('expanded') }, [
                el('span', { class: 'target-chevron', textContent: '>' }),
                el('span', { class: 'target-name', textContent: tgt.hostname }),
                el('span', { class: 'target-ip', textContent: tgt.ip || 'N/A' }),
                el('span', { class: `target-difficulty ${diffClass}`, textContent: diffClass }),
                el('span', { class: `target-status ${tgt.status}`, textContent: tgt.status }),
            ]);

            const actions = el('div', { class: 'target-actions' });
            const delBtn = el('button', {
                class: 'btn btn-sm btn-danger',
                onclick: (e) => { e.stopPropagation(); handleDelete(tgt.hostname); }
            }, ['del']);
            actions.appendChild(delBtn);
            header.appendChild(actions);

            card.appendChild(header);
            card.appendChild(buildTargetDetails(tgt));
            container.appendChild(card);
        }
    }

    function buildTargetDetails(target) {
        const wrap = el('div', { class: 'target-details' });

        // System info
        if (target.system && target.system.user) {
            const sec = el('div', { class: 'detail-section' });
            sec.appendChild(el('div', { class: 'detail-title', textContent: 'System' }));
            const grid = el('div', { class: 'detail-grid' });
            grid.appendChild(makeDetailItem('User', target.system.user, true));
            grid.appendChild(makeDetailItem('Password', target.system.password, true));
            if (target.root_password) {
                grid.appendChild(makeDetailItem('Root Pass', target.root_password, true));
            }
            grid.appendChild(makeDetailItem('Mode', target.mode || 'N/A'));
            grid.appendChild(makeDetailItem('Difficulty', target.difficulty || 'N/A'));
            if (target.deployed_at) {
                grid.appendChild(makeDetailItem('Deployed', new Date(target.deployed_at).toLocaleString()));
            }
            sec.appendChild(grid);
            wrap.appendChild(sec);
        }

        // Services
        if (target.services && target.services.length > 0) {
            const sec = el('div', { class: 'detail-section' });
            sec.appendChild(el('div', { class: 'detail-title', textContent: 'Services' }));
            const grid = el('div', { class: 'detail-grid' });
            for (const svc of target.services) {
                const label = `${svc.type.toUpperCase()} :${svc.port}`;
                let value = '';
                if (svc.creds) value = svc.creds;
                if (svc.details) value += (value ? ' -- ' : '') + svc.details;
                if (svc.database) value += ` [DB: ${svc.database}]`;
                grid.appendChild(makeDetailItem(label, value || '--', !!svc.creds));
            }
            sec.appendChild(grid);
            wrap.appendChild(sec);
        }

        // Flags
        if (target.flags && target.flags.length > 0) {
            const sec = el('div', { class: 'detail-section' });
            sec.appendChild(el('div', { class: 'detail-title', textContent: 'Flags' }));
            const grid = el('div', { class: 'detail-grid' });
            for (const flag of target.flags) {
                grid.appendChild(makeDetailItem(flag.location, flag.value, true, true));
            }
            sec.appendChild(grid);
            wrap.appendChild(sec);
        }

        return wrap;
    }

    function makeDetailItem(label, value, copyable = false, isFlag = false) {
        const item = el('div', { class: 'detail-item' });
        item.appendChild(el('span', { class: 'detail-label', textContent: label }));

        const valWrap = el('span', { class: `detail-value${isFlag ? ' flag-value' : ''}` });
        const valText = (typeof value === 'string' && value.length > 40) ? value.substring(0, 37) + '...' : value;
        valWrap.appendChild(document.createTextNode(valText));

        if (copyable && value) {
            const btn = el('button', {
                class: 'copy-btn',
                textContent: '[cp]',
                title: 'Copy',
                onclick: (e) => { e.stopPropagation(); copyToClipboard(value); }
            });
            valWrap.appendChild(btn);
        }

        item.appendChild(valWrap);
        return item;
    }

    // ==========================================================================
    // Polling
    // ==========================================================================
    function startPolling() {
        if (pollTimer) clearInterval(pollTimer);
        refreshTargets();
        pollTimer = setInterval(refreshTargets, 8000);
    }

    async function refreshTargets() {
        if (!connected) return;
        try {
            const targets = await api('GET', '/api/targets');
            if (Array.isArray(targets)) {
                renderTargets(targets);
            }
        } catch (e) { }
    }

    // ==========================================================================
    // Export handlers
    // ==========================================================================
    function handleDownloadUsers() {
        const users = collectUsers();
        if (users.length === 0) { toast('No targets deployed', 'warn'); return; }
        downloadFile('users.txt', users.join('\n'));
    }

    function handleCopyUsers() {
        const users = collectUsers();
        if (users.length === 0) { toast('No targets deployed', 'warn'); return; }
        copyToClipboard(users.join('\n'));
    }

    function handleDownloadPasswords() {
        const passwords = collectPasswords();
        if (passwords.length === 0) { toast('No targets deployed', 'warn'); return; }
        downloadFile('passwords.txt', passwords.join('\n'));
    }

    function handleCopyPasswords() {
        const passwords = collectPasswords();
        if (passwords.length === 0) { toast('No targets deployed', 'warn'); return; }
        copyToClipboard(passwords.join('\n'));
    }

    function handleReport() {
        window.open('/api/report', '_blank');
    }

    // ==========================================================================
    // Mobile Tabs
    // ==========================================================================
    const MOBILE_BREAKPOINT = 480;
    let mobileMode = false;
    let activeTab = 'deploy';

    function checkMobileMode() {
        const wasMobile = mobileMode;
        mobileMode = window.innerWidth <= MOBILE_BREAKPOINT;

        if (mobileMode && !wasMobile) {
            document.body.classList.add('mobile-tabbed');
            if (connected) {
                $('#mobileTabBar').classList.add('visible');
                switchTab(activeTab);
            }
        } else if (!mobileMode && wasMobile) {
            document.body.classList.remove('mobile-tabbed');
            $('#mobileTabBar').classList.remove('visible');
            // Restore all panels on desktop
            $$('.panel[data-tab]').forEach(p => p.classList.remove('mobile-active'));
        }
    }

    function switchTab(tabName) {
        activeTab = tabName;

        // Update tab bar buttons
        $$('.mobile-tab').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });

        // Show only the active panel
        $$('.panel[data-tab]').forEach(panel => {
            panel.classList.toggle('mobile-active', panel.dataset.tab === tabName);
        });
    }

    function wireMobileTabs() {
        $$('.mobile-tab').forEach(btn => {
            btn.addEventListener('click', () => switchTab(btn.dataset.tab));
        });

        window.addEventListener('resize', checkMobileMode);
        checkMobileMode();
    }

    // ==========================================================================
    // Counter
    // ==========================================================================
    function wireCounter() {
        const input = $('#inputCount');
        $('#btnMinus').addEventListener('click', () => {
            input.value = Math.max(1, parseInt(input.value) - 1);
        });
        $('#btnPlus').addEventListener('click', () => {
            input.value = Math.min(10, parseInt(input.value) + 1);
        });
    }

    // ==========================================================================
    // Check initial status
    // ==========================================================================
    async function checkStatus() {
        try {
            const res = await api('GET', '/api/status');
            if (res.connected) {
                setConnected(true, res.host);
                startSSE();
                startPolling();
            }
        } catch (e) { }
    }

    // ==========================================================================
    // Init
    // ==========================================================================
    function init() {
        $('#btnConnect').addEventListener('click', handleConnect);
        $('#btnDisconnect').addEventListener('click', handleDisconnect);
        $('#btnDeploy').addEventListener('click', handleDeploy);
        $('#btnCleanAll').addEventListener('click', handleCleanAll);
        $('#btnReport').addEventListener('click', handleReport);
        $('#btnClearConsole').addEventListener('click', () => { $('#consoleOutput').innerHTML = ''; });

        // Export
        $('#btnDownloadUsers').addEventListener('click', handleDownloadUsers);
        $('#btnCopyUsers').addEventListener('click', handleCopyUsers);
        $('#btnDownloadPasswords').addEventListener('click', handleDownloadPasswords);
        $('#btnCopyPasswords').addEventListener('click', handleCopyPasswords);

        // Flag validation
        $('#btnValidate').addEventListener('click', handleValidate);
        $('#inputFlag').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') handleValidate();
        });

        // Credential upload
        $('#btnUploadCreds').addEventListener('click', handleUploadCreds);

        // Enter key on password field
        $('#inputPassword').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') handleConnect();
        });

        wireCounter();
        wireMobileTabs();
        checkStatus();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
