document.addEventListener("DOMContentLoaded", () => {
    // ─── Elements ───
    const startBtn = document.getElementById("start-task-btn");
    const taskNameInput = document.getElementById("task_name");
    const qtyInput = document.getElementById("task_qty");
    const taskStatus = document.getElementById("task-status");
    const taskListEl = document.getElementById("task-list");
    const terminalBody = document.getElementById("terminal-body");
    const downloadTaskLogBtn = document.getElementById("download-task-log-btn");

    // Stats
    const statPending = document.getElementById("stat-pending");
    const statRunning = document.getElementById("stat-running");
    const statCompleted = document.getElementById("stat-completed");
    const statFailed = document.getElementById("stat-failed");

    // Logs state
    const LAST_LOG_TASK_KEY = "lastLogTaskId";
    let taskLogs = { "sys": [{text: "系统就绪，等待任务创建...", type: "sys"}] };
    let loadedTaskLogs = new Set();
    const savedLogTaskId = parseInt(localStorage.getItem(LAST_LOG_TASK_KEY));
    let currentLogTaskId = Number.isInteger(savedLogTaskId) ? savedLogTaskId : "sys";
    let logRenderVersion = 0;

    function switchLogView(taskId) {
        currentLogTaskId = taskId;
        if (taskId === "sys") {
            localStorage.removeItem(LAST_LOG_TASK_KEY);
        } else {
            localStorage.setItem(LAST_LOG_TASK_KEY, String(taskId));
        }
        let logs = taskLogs[taskId] || [];
        renderLogList(logs);
        
        const titleLabel = document.getElementById("current-task-label");
        if (titleLabel) {
            titleLabel.textContent = taskId === "sys" ? " - 系统日志" : ` - 任务 #${taskId}`;
        }
        if (downloadTaskLogBtn) {
            downloadTaskLogBtn.disabled = taskId === "sys";
        }
        
        document.querySelectorAll(".task-item").forEach(el => {
            if (parseInt(el.getAttribute("data-id")) === taskId) {
                el.classList.add("active-task");
            } else {
                el.classList.remove("active-task");
            }
        });

        if (taskId !== "sys" && !loadedTaskLogs.has(taskId)) {
            fetch(`/api/tasks/${taskId}/logs`)
                .then(response => response.ok ? response.json() : Promise.reject())
                .then(data => {
                    taskLogs[taskId] = (data.logs || []).map(text => ({
                        text,
                        type: logType(text),
                    }));
                    loadedTaskLogs.add(taskId);
                    if (currentLogTaskId === taskId) {
                        renderLogList(taskLogs[taskId]);
                    }
                })
                .catch(() => {});
        }
    }

    function renderLogList(logs) {
        const version = ++logRenderVersion;
        const chunkSize = 500;
        let index = 0;
        terminalBody.innerHTML = "";

        function renderChunk() {
            if (version !== logRenderVersion) return;
            const fragment = document.createDocumentFragment();
            const end = Math.min(index + chunkSize, logs.length);
            for (; index < end; index++) {
                fragment.appendChild(createLogLine(logs[index]));
            }
            terminalBody.appendChild(fragment);
            if (index < logs.length) {
                requestAnimationFrame(renderChunk);
            } else {
                terminalBody.scrollTop = terminalBody.scrollHeight;
            }
        }

        renderChunk();
    }

    function createLogLine(entry) {
        const line = document.createElement("div");
        line.className = `log-line ${entry.type}`;
        line.textContent = entry.text;
        return line;
    }

    function renderSingleLog(entry) {
        terminalBody.appendChild(createLogLine(entry));
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    // ────────────────── Create Task ──────────────────
    const concurrencyInput = document.getElementById("task_concurrency");
    const showBrowserCb = document.getElementById("show_browser");
    const emailSourceInput = document.getElementById("email_source");
    const registrationModeInput = document.getElementById("registration_mode");
    const emailSourceGroup = document.getElementById("email-source-group");
    const inviteAccountGroup = document.getElementById("invite-account-group");
    const inviteAccountList = document.getElementById("invite-account-list");
    const inviteAccountCount = document.getElementById("invite-account-count");
    const selectAllInviteAccounts = document.getElementById("select-all-invite-accounts");
    const inviteRemoveMembersInput = document.getElementById("invite_remove_members");

    function emailSourceLabel(source) {
        return source === "self" ? "自备邮箱" : "临时邮箱";
    }

    function registrationModeLabel(mode) {
        return mode === "invite" ? "邀请模式" : "普通注册";
    }

    function logType(text) {
        if (text.includes("❌") || text.includes("⚠️")) return "error";
        if (text.includes("✅") || text.includes("🎉")) return "success";
        if (text.includes("系统") || text.includes("📋") || text.includes("🏁")) return "sys";
        return "info";
    }

    function selectedAdobeAccountIds() {
        return Array.from(inviteAccountList.querySelectorAll("input[type='checkbox']:checked")).map(input => input.value);
    }

    function updateInviteAccountCount() {
        const count = selectedAdobeAccountIds().length;
        inviteAccountCount.textContent = count ? `已选 ${count} 个` : "请选择账号";
        const checks = [...inviteAccountList.querySelectorAll("input[type='checkbox']")];
        selectAllInviteAccounts.disabled = checks.length === 0;
        selectAllInviteAccounts.checked = checks.length > 0 && count === checks.length;
        selectAllInviteAccounts.indeterminate = count > 0 && count < checks.length;
    }

    function loadInviteAccounts() {
        fetch("/api/adobe-accounts")
            .then(response => response.json())
            .then(accounts => {
                inviteAccountList.innerHTML = accounts.length ? accounts.map((account, index) => `
                    <label class="invite-account-option">
                        <input type="checkbox" value="${account.id}">
                        <span class="invite-account-sequence">${index + 1}</span>
                        <span class="invite-account-avatar">${(account.name || "A").slice(0, 1).toUpperCase()}</span>
                        <span class="invite-account-info">
                            <strong>${account.name || "未命名账号"}</strong>
                            <small>${account.organization_id || "尚未检测组织"}</small>
                        </span>
                    </label>
                `).join("") : '<div class="empty-hint">暂无账号，请先前往账号页面配置</div>';
                updateInviteAccountCount();
            })
            .catch(() => {
                inviteAccountList.innerHTML = '<div class="empty-hint">账号读取失败</div>';
                updateInviteAccountCount();
            });
    }

    registrationModeInput.addEventListener("change", () => {
        const invite = registrationModeInput.value === "invite";
        inviteAccountGroup.hidden = !invite;
        emailSourceGroup.hidden = invite;
        if (invite) emailSourceInput.value = "self";
    });
    inviteAccountList.addEventListener("change", updateInviteAccountCount);
    selectAllInviteAccounts.addEventListener("change", () => {
        inviteAccountList.querySelectorAll("input[type='checkbox']").forEach(input => {
            input.checked = selectAllInviteAccounts.checked;
        });
        updateInviteAccountCount();
    });
    loadInviteAccounts();

    startBtn.addEventListener("click", () => {
        const qty = parseInt(qtyInput.value) || 1;
        const conc = parseInt(concurrencyInput.value) || 1;
        const showBrowser = showBrowserCb.checked;
        const taskName = (taskNameInput.value || "").trim();
        const registrationMode = registrationModeInput ? registrationModeInput.value : "standard";
        const emailSource = registrationMode === "invite" ? "self" : (emailSourceInput ? emailSourceInput.value : "temp");
        const adobeAccountIds = registrationMode === "invite" ? selectedAdobeAccountIds() : [];
        if (registrationMode === "invite" && !adobeAccountIds.length) {
            taskStatus.style.color = "var(--danger)";
            taskStatus.textContent = "邀请模式至少选择一个团队账号";
            return;
        }

        startBtn.disabled = true;
        startBtn.textContent = "加入中...";

        fetch("/api/tasks", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                name: taskName,
                quantity: qty,
                concurrency: conc,
                show_browser: showBrowser,
                email_source: emailSource,
                registration_mode: registrationMode,
                adobe_account_ids: adobeAccountIds,
                invite_remove_members: registrationMode === "invite" ? inviteRemoveMembersInput.checked : false,
            })
        }).then(async r => {
            const data = await r.json();
            if (!r.ok) throw new Error(data.message || "任务创建失败");
            return data;
        }).then(data => {
            startBtn.disabled = false;
            startBtn.textContent = "加入队列";
            taskStatus.style.color = "var(--success)";
            taskStatus.textContent = `✅ ${data.name} 已创建 (${data.quantity}个, 并发${data.concurrency} · ${registrationModeLabel(data.registration_mode)})`;
            setTimeout(() => taskStatus.textContent = "", 3000);
            appendLog(`系统: ${data.name} 已加入队列 (#${data.id}, ${data.quantity}个注册, 并发${data.concurrency} · ${registrationModeLabel(data.registration_mode)})`, "sys");
            refreshTaskList();
        }).catch(error => {
            startBtn.disabled = false;
            startBtn.textContent = "加入队列";
            taskStatus.style.color = "var(--danger)";
            taskStatus.textContent = error.message || "任务创建失败";
        });
    });

    // ────────────────── Task List ──────────────────
    function refreshTaskList() {
        fetch("/api/tasks")
            .then(r => r.json())
            .then(tasks => {
                // Update stats
                let pending = 0, running = 0, completed = 0, failed = 0;
                tasks.forEach(t => {
                    if (t.status === "pending") pending += t.quantity;
                    else if (t.status === "running") {
                        running += (t.quantity - t.completed - t.failed);
                        completed += t.completed;
                        failed += t.failed;
                    } else {
                        completed += t.completed;
                        failed += t.failed;
                    }
                });
                statPending.textContent = pending;
                statRunning.textContent = running;
                statCompleted.textContent = completed;
                statFailed.textContent = failed;

                if (tasks.length === 0) {
                    taskListEl.innerHTML = '<div class="empty-hint">暂无任务</div>';
                    localStorage.removeItem(LAST_LOG_TASK_KEY);
                    if (currentLogTaskId !== "sys") switchLogView("sys");
                    return;
                }
                
                // Keep the selected task across refreshes; fall back only if it was deleted.
                let currentItem = tasks.find(t => t.id === currentLogTaskId);
                if (!currentItem) {
                    let activeTask = tasks.find(t => t.status === "running") || tasks.find(t => t.status === "stopping") || tasks.find(t => t.status === "pending");
                    let fallbackTask = activeTask || tasks[0];
                    switchLogView(fallbackTask.id);
                }

                // Show latest 10
                taskListEl.innerHTML = tasks.slice(0, 10).map(t => {
                    let badgeClass = t.status;
                    let badgeText = { pending: "排队中", running: "运行中", completed: "已完成", stopped: "已停止", stopping: "停止中..." }[t.status] || t.status;
                    let activeClass = t.id === currentLogTaskId ? " active-task" : "";
                    return `
                        <div class="task-item${activeClass}" data-id="${t.id}" style="cursor: pointer;">
                            <div class="task-left">
                                <span class="task-id">${t.name || `任务 #${t.id}`}</span>
                                <span class="task-meta">#${t.id} · ${t.created_at} · ${registrationModeLabel(t.registration_mode)} · ${t.quantity}个 · 并发${t.concurrency}</span>
                            </div>
                            <div class="task-right">
                                <div class="task-counts">
                                    <span class="ok">${t.completed}</span> / <span class="fail">${t.failed}</span>
                                    <span class="pool">入池 ${t.token_pool_imported || 0}</span>
                                    <span class="unpooled">未入池 ${t.token_pool_unpooled || 0}</span>
                                </div>
                                <span class="badge ${badgeClass}">${badgeText}</span>
                                ${["pending", "running"].includes(t.status) ? `<button class="btn-sm danger stop-task-btn" data-id="${t.id}" style="margin-left: 8px;">停止</button>` : ''}
                            </div>
                        </div>
                    `;
                }).join("");
            });
    }

    taskListEl.addEventListener("click", (e) => {
        if (e.target.classList.contains("stop-task-btn")) {
            const taskId = parseInt(e.target.getAttribute("data-id"));
            if (confirm(`确认要停止任务 #${taskId} 吗？`)) {
                e.target.disabled = true;
                e.target.textContent = "停止中...";
                fetch("/api/tasks/stop", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({ ids: [taskId] })
                }).then(() => refreshTaskList());
            }
            return;
        }

        const item = e.target.closest(".task-item");
        if (item) {
            const taskId = parseInt(item.getAttribute("data-id"));
            if (taskId) switchLogView(taskId);
        }
    });

    setInterval(refreshTaskList, 2000);
    refreshTaskList();

    // ────────────────── WebSocket Logs ──────────────────
    let protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    let wsUrl = `${protocol}//${window.location.host}/ws/logs`;

    function connectWS() {
        const ws = new WebSocket(wsUrl);

        ws.onmessage = (event) => {
            const msg = event.data;
            if (msg === "__STATE_UPDATE__") {
                refreshTaskList();
                return;
            }
            appendLog(msg, logType(msg));
        };

        ws.onclose = () => {
            setTimeout(connectWS, 3000);
        };
    }

    function appendLog(text, type = "info") {
        let tid = null;
        let match = text.match(/\[任务#(\d+)(?:[-\s·\]])/);
        if (!match) match = text.match(/任务\s*#(\d+)/);
        if (match) tid = parseInt(match[1]);

        let entry = { text, type };
        if (tid) {
            if (!taskLogs[tid]) taskLogs[tid] = [];
            taskLogs[tid].push(entry);
        } else {
            taskLogs["sys"].push(entry);
        }

        if (tid === currentLogTaskId || (!tid && currentLogTaskId === "sys")) {
            renderSingleLog(entry);
        }
    }

    const expandBtn = document.getElementById("expand-terminal-btn");
    if (downloadTaskLogBtn) {
        downloadTaskLogBtn.addEventListener("click", () => {
            if (currentLogTaskId === "sys") return;
            window.location.href = `/api/tasks/${currentLogTaskId}/logs/download`;
        });
    }

    if (expandBtn) {
        expandBtn.addEventListener("click", () => {
            const card = document.querySelector(".terminal-card");
            card.classList.toggle("fullscreen");
            expandBtn.textContent = card.classList.contains("fullscreen") ? "收起 ✖" : "展开 ⛶";
            if (!card.classList.contains("fullscreen")) {
                terminalBody.scrollTo({ top: terminalBody.scrollHeight, behavior: "smooth" });
            }
        });
    }

    switchLogView(currentLogTaskId);
    connectWS();
});
