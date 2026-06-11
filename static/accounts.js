document.addEventListener("DOMContentLoaded", () => {
    const listEl = document.getElementById("account-list");
    const idInput = document.getElementById("account-id");
    const nameInput = document.getElementById("account-name");
    const cookieInput = document.getElementById("account-cookie");
    const cookieJsonInput = document.getElementById("cookie-json-input");
    const statusEl = document.getElementById("account-status");
    const selectedPill = document.getElementById("selected-account-pill");
    const testBtn = document.getElementById("test-account-btn");
    const deleteBtn = document.getElementById("delete-account-btn");
    const selectAllAccounts = document.getElementById("select-all-accounts");
    const deleteSelectedAccountsBtn = document.getElementById("delete-selected-accounts-btn");
    const accountPageLabel = document.getElementById("account-page-label");
    const accountPrevBtn = document.getElementById("account-prev-btn");
    const accountNextBtn = document.getElementById("account-next-btn");
    const inviteBtn = document.getElementById("invite-btn");
    const removeSelectedBtn = document.getElementById("remove-selected-members-btn");
    const selectAllMembers = document.getElementById("select-all-members");
    const refreshMembersBtn = document.getElementById("refresh-members-btn");
    const memberSearch = document.getElementById("member-search");
    const memberRows = document.getElementById("member-rows");
    const memberSummary = document.getElementById("member-summary");
    const memberPageLabel = document.getElementById("member-page-label");
    const memberPrevBtn = document.getElementById("member-prev-btn");
    const memberNextBtn = document.getElementById("member-next-btn");
    const logEl = document.getElementById("operation-log");
    let accounts = [];
    let selectedId = "";
    let memberPage = 0;
    let memberHasMore = false;
    let selectedMemberEmails = new Set();
    let selectedAccountIds = new Set();
    let accountPage = 0;
    const accountPageSize = 10;

    function showStatus(message, ok) {
        statusEl.textContent = message;
        statusEl.style.color = ok ? "var(--success)" : "var(--danger)";
    }

    async function api(url, options = {}) {
        const response = await fetch(url, options);
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || data.detail || "请求失败");
        return data;
    }

    function setSelected(id) {
        selectedId = id;
        const account = accounts.find(item => item.id === id);
        idInput.value = id;
        nameInput.value = account?.name || "";
        cookieInput.value = "";
        selectedPill.textContent = account ? `当前账号 · ${account.name}` : "未选择账号";
        testBtn.disabled = !account;
        deleteBtn.disabled = !account;
        inviteBtn.disabled = !account;
        removeSelectedBtn.disabled = true;
        selectAllMembers.checked = false;
        selectAllMembers.disabled = true;
        selectedMemberEmails.clear();
        refreshMembersBtn.disabled = !account;
        memberPage = 0;
        memberHasMore = false;
        memberRows.innerHTML = '<tr><td colspan="6" class="empty-state">尚未读取成员</td></tr>';
        memberSummary.textContent = account ? "点击“刷新成员”读取 Adobe Admin Console 成员。" : "选择账号后可读取 Adobe Admin Console 成员。";
        updateMemberPagination();
        renderAccounts();
    }

    function renderAccounts() {
        const totalPages = Math.max(1, Math.ceil(accounts.length / accountPageSize));
        accountPage = Math.min(accountPage, totalPages - 1);
        if (!accounts.length) {
            selectedAccountIds.clear();
            selectAllAccounts.disabled = true;
            selectAllAccounts.checked = false;
            selectAllAccounts.indeterminate = false;
            deleteSelectedAccountsBtn.disabled = true;
            deleteSelectedAccountsBtn.textContent = "删除选中";
            listEl.innerHTML = '<div class="empty-hint">暂未配置账号</div>';
            updateAccountPagination();
            return;
        }
        selectedAccountIds = new Set([...selectedAccountIds].filter(id => accounts.some(account => account.id === id)));
        const pageStart = accountPage * accountPageSize;
        const pageAccounts = accounts.slice(pageStart, pageStart + accountPageSize);
        listEl.innerHTML = pageAccounts.map((account, index) => `
            <div class="account-item ${account.id === selectedId ? "active" : ""}" data-id="${account.id}">
                <label class="account-batch-check-wrap" title="选择账号">
                    <input class="account-batch-check" type="checkbox" value="${account.id}" ${selectedAccountIds.has(account.id) ? "checked" : ""} aria-label="选择 ${escapeHtml(account.name)}">
                </label>
                <button class="account-select-btn" data-id="${account.id}">
                    <span class="account-sequence">${pageStart + index + 1}</span>
                    <span class="account-avatar">${escapeHtml(account.name.slice(0, 1).toUpperCase())}</span>
                    <span class="account-copy">
                        <strong>${escapeHtml(account.name)}</strong>
                        <small>${escapeHtml(account.cookie_preview || "未配置 Cookie")}</small>
                        ${renderSubscriptionSummary(account.subscriptions)}
                        ${account.token_expires_at ? `<small>Token 预计有效至 ${escapeHtml(account.token_expires_at)}</small>` : ""}
                    </span>
                    <span class="account-dot ${account.cookie_configured ? "ready" : ""}"></span>
                </button>
                <button class="account-inline-delete" data-id="${account.id}" title="删除账号" aria-label="删除 ${escapeHtml(account.name)}">×</button>
            </div>
        `).join("");
        updateAccountSelection();
        updateAccountPagination();
    }

    function updateAccountPagination() {
        const totalPages = Math.max(1, Math.ceil(accounts.length / accountPageSize));
        accountPageLabel.textContent = `第 ${accountPage + 1} / ${totalPages} 页 · 共 ${accounts.length} 个`;
        accountPrevBtn.disabled = accountPage <= 0;
        accountNextBtn.disabled = accountPage >= totalPages - 1;
    }

    function updateAccountSelection() {
        const checks = [...listEl.querySelectorAll(".account-batch-check")];
        selectedAccountIds = new Set(checks.filter(input => input.checked).map(input => input.value));
        selectAllAccounts.disabled = checks.length === 0;
        selectAllAccounts.checked = checks.length > 0 && selectedAccountIds.size === checks.length;
        selectAllAccounts.indeterminate = selectedAccountIds.size > 0 && selectedAccountIds.size < checks.length;
        deleteSelectedAccountsBtn.disabled = selectedAccountIds.size === 0;
        deleteSelectedAccountsBtn.textContent = selectedAccountIds.size
            ? `删除选中 (${selectedAccountIds.size})`
            : "删除选中";
    }

    function renderSubscriptionSummary(subscriptions = []) {
        const primary = subscriptions.find(item => item.end_date);
        if (!primary) return "";
        return `<small class="subscription-summary">有效期 ${escapeHtml(primary.end_date)}</small>`;
    }

    async function loadAccounts(preferredId = "") {
        accounts = await api("/api/adobe-accounts");
        const preferredIndex = accounts.findIndex(item => item.id === preferredId);
        if (preferredIndex >= 0) accountPage = Math.floor(preferredIndex / accountPageSize);
        const totalPages = Math.max(1, Math.ceil(accounts.length / accountPageSize));
        accountPage = Math.min(accountPage, totalPages - 1);
        const pageFirstAccount = accounts[accountPage * accountPageSize];
        const currentStillExists = accounts.some(item => item.id === selectedId);
        const nextId = preferredId || (currentStillExists ? selectedId : pageFirstAccount?.id) || accounts[0]?.id || "";
        setSelected(accounts.some(item => item.id === nextId) ? nextId : "");
    }

    function parseEmails(value) {
        return [...new Set(value.split(/[\n,;]+/).map(item => item.trim().toLowerCase()).filter(Boolean))];
    }

    function cookieHeaderFromJson(data) {
        if (typeof data?.cookie === "string" && data.cookie.trim()) return data.cookie.trim();
        const cookies = Array.isArray(data) ? data : data?.cookies;
        if (!Array.isArray(cookies)) {
            throw new Error('JSON 中未找到 "cookie" 字符串或 Cookie 数组');
        }
        const valid = cookies.filter(item => item && typeof item.name === "string" && "value" in item);
        if (!valid.length) throw new Error("Cookie 数组中没有有效的 name/value 项");
        return valid.map(item => `${item.name}=${item.value ?? ""}`).join("; ");
    }

    function renderResults(title, results) {
        const time = new Date().toLocaleTimeString();
        const rows = results.map(result => `
            <div class="operation-row ${result.ok ? "success" : "failure"}">
                <span class="operation-mark">${result.ok ? "✓" : "×"}</span>
                <span><strong>${result.email || title}</strong><small>${result.message}</small></span>
                <time>${time}</time>
            </div>
        `).join("");
        if (logEl.querySelector(".empty-hint")) logEl.innerHTML = "";
        logEl.insertAdjacentHTML("afterbegin", rows);
    }

    function escapeHtml(value) {
        return String(value ?? "").replace(/[&<>"']/g, char => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
        })[char]);
    }

    function updateMemberPagination() {
        memberPageLabel.textContent = `第 ${memberPage + 1} 页`;
        memberPrevBtn.disabled = memberPage <= 0;
        memberNextBtn.disabled = !memberHasMore;
    }

    function updateMemberSelection() {
        const selectable = [...memberRows.querySelectorAll(".member-check:not(:disabled)")];
        const checked = selectable.filter(input => input.checked);
        selectedMemberEmails = new Set(checked.map(input => input.dataset.email));
        removeSelectedBtn.disabled = selectedMemberEmails.size === 0;
        selectAllMembers.disabled = selectable.length === 0;
        selectAllMembers.checked = selectable.length > 0 && checked.length === selectable.length;
        selectAllMembers.indeterminate = checked.length > 0 && checked.length < selectable.length;
    }

    async function loadMembers() {
        if (!selectedId) return;
        refreshMembersBtn.disabled = true;
        refreshMembersBtn.textContent = "读取中...";
        selectedMemberEmails.clear();
        updateMemberSelection();
        memberRows.innerHTML = '<tr><td colspan="6" class="empty-state">正在连接 Adobe JIL API...</td></tr>';
        try {
            const query = new URLSearchParams({
                page: memberPage,
                page_size: 20,
                search: memberSearch.value.trim(),
            });
            const data = await api(`/api/adobe-accounts/${selectedId}/members?${query}`);
            memberHasMore = data.has_more;
            memberSummary.textContent = `组织 ${data.organization_id} · 本页 ${data.members.length} 名成员`;
            if (!data.members.length) {
                memberRows.innerHTML = '<tr><td colspan="6" class="empty-state">没有匹配成员</td></tr>';
            } else {
                memberRows.innerHTML = data.members.map(member => `
                    <tr>
                        <td><input class="member-check" type="checkbox" data-email="${escapeHtml(member.email)}" ${member.removable && !member.protected ? "" : "disabled"} aria-label="选择 ${escapeHtml(member.email)}"></td>
                        <td>
                            <strong>${escapeHtml([member.first_name, member.last_name].filter(Boolean).join(" ") || member.email)}</strong>
                            <small>${escapeHtml(member.email)}</small>
                        </td>
                        <td>${escapeHtml(member.type || "-")}</td>
                        <td>${member.products}</td>
                        <td><span class="member-status">${escapeHtml(member.account_status || "-")}</span></td>
                        <td>
                            ${member.protected
                                ? '<span class="protected-account-badge">主账号</span>'
                                : `<button class="btn-sm danger queue-remove-btn" data-email="${escapeHtml(member.email)}" ${member.removable ? "" : "disabled"}>移除</button>`}
                        </td>
                    </tr>
                `).join("");
            }
            updateMemberSelection();
            updateMemberPagination();
        } catch (error) {
            memberRows.innerHTML = `<tr><td colspan="6" class="empty-state danger-text">${escapeHtml(error.message)}</td></tr>`;
            memberSummary.textContent = "成员读取失败";
            memberHasMore = false;
            updateMemberPagination();
        } finally {
            refreshMembersBtn.disabled = !selectedId;
            refreshMembersBtn.textContent = "刷新成员";
        }
    }

    document.getElementById("new-account-btn").addEventListener("click", () => {
        setSelected("");
        nameInput.focus();
        showStatus("正在新增账号，请填写名称和 Cookie", true);
    });

    cookieJsonInput.addEventListener("change", async () => {
        const file = cookieJsonInput.files?.[0];
        if (!file) return;
        try {
            const data = JSON.parse(await file.text());
            const cookie = cookieHeaderFromJson(data);
            if (selectedId) setSelected("");
            cookieInput.value = cookie;
            if (!nameInput.value.trim()) {
                nameInput.value = file.name.replace(/\.json$/i, "").replace(/^cookie[_-]?/i, "") || "Adobe 团队账号";
            }
            showStatus(`已导入 ${file.name}，请确认名称后保存账号`, true);
        } catch (error) {
            showStatus(`导入失败：${error.message}`, false);
        } finally {
            cookieJsonInput.value = "";
        }
    });

    listEl.addEventListener("click", event => {
        if (event.target.classList.contains("account-batch-check")) {
            updateAccountSelection();
            return;
        }
        const deleteButton = event.target.closest(".account-inline-delete");
        if (deleteButton) {
            deleteAccount(deleteButton.dataset.id);
            return;
        }
        const selectButton = event.target.closest(".account-select-btn");
        if (selectButton) setSelected(selectButton.dataset.id);
    });

    document.getElementById("save-account-btn").addEventListener("click", async event => {
        const button = event.currentTarget;
        button.disabled = true;
        button.textContent = "保存中...";
        try {
            const account = await api("/api/adobe-accounts", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    id: idInput.value,
                    name: nameInput.value,
                    cookie: cookieInput.value,
                }),
            });
            await loadAccounts(account.id);
            showStatus("账号配置已保存", true);
        } catch (error) {
            showStatus(error.message, false);
        } finally {
            button.disabled = false;
            button.textContent = "保存账号";
        }
    });

    testBtn.addEventListener("click", async () => {
        testBtn.disabled = true;
        testBtn.textContent = "检查中...";
        try {
            const result = await api(`/api/adobe-accounts/${selectedId}/test`, {method: "POST"});
            showStatus(result.message, true);
            renderResults("Cookie 检查", [{ok: true, message: result.message}]);
        } catch (error) {
            showStatus(error.message, false);
            renderResults("Cookie 检查", [{ok: false, message: error.message}]);
        } finally {
            testBtn.disabled = false;
            testBtn.textContent = "检查 Cookie";
        }
    });

    async function deleteAccount(accountId, askConfirmation = true, reload = true) {
        const account = accounts.find(item => item.id === accountId);
        if (!account || (askConfirmation && !confirm(`确认删除账号“${account.name}”的 Cookie 配置吗？`))) return false;
        deleteBtn.disabled = true;
        try {
            await api(`/api/adobe-accounts/${accountId}`, {method: "DELETE"});
            if (accountId === selectedId) selectedId = "";
            selectedAccountIds.delete(accountId);
            if (reload) {
                await loadAccounts(selectedId);
                showStatus("账号配置已删除", true);
            }
            return true;
        } catch (error) {
            showStatus(error.message, false);
            return false;
        } finally {
            deleteBtn.disabled = false;
        }
    }

    deleteBtn.addEventListener("click", async () => {
        await deleteAccount(selectedId);
    });

    selectAllAccounts.addEventListener("change", () => {
        listEl.querySelectorAll(".account-batch-check").forEach(input => {
            input.checked = selectAllAccounts.checked;
        });
        updateAccountSelection();
    });

    accountPrevBtn.addEventListener("click", () => {
        accountPage = Math.max(0, accountPage - 1);
        selectedAccountIds.clear();
        renderAccounts();
    });

    accountNextBtn.addEventListener("click", () => {
        const totalPages = Math.max(1, Math.ceil(accounts.length / accountPageSize));
        accountPage = Math.min(totalPages - 1, accountPage + 1);
        selectedAccountIds.clear();
        renderAccounts();
    });

    deleteSelectedAccountsBtn.addEventListener("click", async () => {
        const ids = [...selectedAccountIds];
        if (!ids.length || !confirm(`确认删除选中的 ${ids.length} 个账号凭据吗？此操作无法撤销。`)) return;
        deleteSelectedAccountsBtn.disabled = true;
        deleteSelectedAccountsBtn.textContent = "正在删除...";
        let deleted = 0;
        for (const id of ids) {
            if (await deleteAccount(id, false, false)) deleted += 1;
        }
        await loadAccounts(selectedId);
        showStatus(`已删除 ${deleted} 个账号凭据`, deleted === ids.length);
    });

    async function runTeamAction(kind, suppliedEmails = null) {
        const isRemove = kind === "remove";
        const button = isRemove ? removeSelectedBtn : inviteBtn;
        const textarea = document.getElementById("invite-emails");
        const emails = suppliedEmails || parseEmails(textarea.value);
        if (!emails.length) {
            renderResults("输入检查", [{ok: false, message: "请至少填写一个有效邮箱"}]);
            return false;
        }
        if (isRemove && !confirm(`确认从团队移除 ${emails.length} 个成员吗？`)) return false;
        button.disabled = true;
        button.textContent = isRemove ? "正在移除..." : "正在发送...";
        try {
            const result = await api(`/api/adobe-team/${kind}`, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({account_id: selectedId, emails}),
            });
            renderResults(isRemove ? "移除成员" : "邀请成员", result.results);
            return true;
        } catch (error) {
            renderResults("执行失败", [{ok: false, message: error.message}]);
            return false;
        } finally {
            button.disabled = false;
            button.textContent = isRemove ? "移除选中" : "发送邀请";
        }
    }

    inviteBtn.addEventListener("click", () => runTeamAction("invite"));
    removeSelectedBtn.addEventListener("click", async () => {
        if (await runTeamAction("remove", [...selectedMemberEmails])) await loadMembers();
    });
    selectAllMembers.addEventListener("change", () => {
        memberRows.querySelectorAll(".member-check:not(:disabled)").forEach(input => {
            input.checked = selectAllMembers.checked;
        });
        updateMemberSelection();
    });
    refreshMembersBtn.addEventListener("click", () => {
        memberPage = 0;
        loadMembers();
    });
    memberSearch.addEventListener("keydown", event => {
        if (event.key === "Enter") {
            memberPage = 0;
            loadMembers();
        }
    });
    memberPrevBtn.addEventListener("click", () => {
        memberPage = Math.max(0, memberPage - 1);
        loadMembers();
    });
    memberNextBtn.addEventListener("click", () => {
        memberPage += 1;
        loadMembers();
    });
    memberRows.addEventListener("click", event => {
        const button = event.target.closest(".queue-remove-btn");
        if (button) {
            runTeamAction("remove", [button.dataset.email]).then(ok => {
                if (ok) loadMembers();
            });
            return;
        }
        if (event.target.classList.contains("member-check")) updateMemberSelection();
    });
    document.getElementById("clear-log-btn").addEventListener("click", () => {
        logEl.innerHTML = '<div class="empty-hint">等待执行团队操作</div>';
    });

    loadAccounts().catch(error => showStatus(error.message, false));
});
