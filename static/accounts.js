document.addEventListener("DOMContentLoaded", () => {
    const listEl = document.getElementById("account-list");
    const idInput = document.getElementById("account-id");
    const emailInput = document.getElementById("account-email");
    const hotmailPasswordInput = document.getElementById("hotmail-password");
    const adobePasswordInput = document.getElementById("adobe-password");
    const clientIdInput = document.getElementById("client-id");
    const refreshTokenInput = document.getElementById("refresh-token");
    const statusEl = document.getElementById("account-status");
    const selectedPill = document.getElementById("selected-account-pill");
    const testBtn = document.getElementById("test-account-btn");
    const deleteBtn = document.getElementById("delete-account-btn");
    const selectAllAccounts = document.getElementById("select-all-accounts");
    const testSelectedAccountsBtn = document.getElementById("test-selected-accounts-btn");
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
    const batchContent = document.getElementById("batch-import-content");
    let accounts = [];
    let selectedId = "";
    let selectedAccountIds = new Set();
    let memberPage = 0;
    let memberHasMore = false;
    let accountPage = 0;
    const accountPageSize = 10;

    function escapeHtml(value) {
        return String(value ?? "").replace(/[&<>"']/g, char => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
        })[char]);
    }

    function showStatus(message, ok) {
        statusEl.textContent = message;
        statusEl.style.color = ok ? "var(--success)" : "var(--danger)";
    }

    async function api(url, options = {}) {
        const response = await fetch(url, options);
        const data = await response.json();
        if (!response.ok) {
            const error = new Error(data.message || data.detail || "请求失败");
            Object.assign(error, data);
            throw error;
        }
        return data;
    }

    function parseEmails(value) {
        return [...new Set(value.split(/[\n,;]+/).map(item => item.trim().toLowerCase()).filter(Boolean))];
    }

    function accountStatusText(account) {
        if (account.has_org) return account.product_name || "已获取管理权限";
        if (account.is_valid === false) return account.check_message || "检测失败";
        if (account.credential_configured) return "待协议检测";
        return "未配置凭证";
    }

    function setSelected(id) {
        selectedId = id;
        const account = accounts.find(item => item.id === id);
        idInput.value = id || "";
        emailInput.value = account?.email || "";
        hotmailPasswordInput.value = account?.hotmail_password || "";
        adobePasswordInput.value = account?.adobe_password || "";
        clientIdInput.value = account?.client_id || "";
        refreshTokenInput.value = account?.refresh_token || "";
        selectedPill.textContent = account ? `当前母号 · ${account.email || account.name}` : "未选择母号";
        testBtn.disabled = !account;
        deleteBtn.disabled = !account;
        inviteBtn.disabled = !account;
        refreshMembersBtn.disabled = !account;
        removeSelectedBtn.disabled = true;
        selectAllMembers.checked = false;
        selectAllMembers.disabled = true;
        memberPage = 0;
        memberHasMore = false;
        memberRows.innerHTML = '<tr><td colspan="6" class="empty-state">尚未读取成员</td></tr>';
        memberSummary.textContent = account ? "点击刷新成员读取 Adobe 组织成员。" : "选择母号后可读取成员。";
        updateMemberPagination();
        renderAccounts();
    }

    function pageAccountIds() {
        const pageStart = accountPage * accountPageSize;
        return accounts.slice(pageStart, pageStart + accountPageSize).map(account => account.id);
    }

    function updateAccountBulkSelection() {
        const validIds = new Set(accounts.map(account => account.id));
        selectedAccountIds = new Set([...selectedAccountIds].filter(id => validIds.has(id)));
        const selectedCount = selectedAccountIds.size;
        const pageIds = pageAccountIds();
        const checkedOnPage = pageIds.filter(id => selectedAccountIds.has(id)).length;
        if (selectAllAccounts) {
            selectAllAccounts.disabled = pageIds.length === 0;
            selectAllAccounts.checked = pageIds.length > 0 && checkedOnPage === pageIds.length;
            selectAllAccounts.indeterminate = checkedOnPage > 0 && checkedOnPage < pageIds.length;
        }
        if (testSelectedAccountsBtn) {
            testSelectedAccountsBtn.disabled = selectedCount === 0;
            testSelectedAccountsBtn.textContent = selectedCount ? `检测选中 ${selectedCount}` : "检测选中";
        }
        if (deleteSelectedAccountsBtn) {
            deleteSelectedAccountsBtn.disabled = selectedCount === 0;
            deleteSelectedAccountsBtn.textContent = selectedCount ? `删除选中 ${selectedCount}` : "删除选中";
        }
    }

    function renderAccounts() {
        const totalPages = Math.max(1, Math.ceil(accounts.length / accountPageSize));
        accountPage = Math.min(accountPage, totalPages - 1);
        if (!accounts.length) {
            listEl.innerHTML = '<div class="empty-hint">尚未导入母号</div>';
            updateAccountPagination();
            updateAccountBulkSelection();
            return;
        }
        const pageStart = accountPage * accountPageSize;
        const pageAccounts = accounts.slice(pageStart, pageStart + accountPageSize);
        listEl.innerHTML = pageAccounts.map((account, index) => `
            <div class="account-item ${account.id === selectedId ? "active" : ""}">
                <label class="account-batch-check-wrap" title="选择母号">
                    <input class="account-batch-check" type="checkbox" data-id="${account.id}" ${selectedAccountIds.has(account.id) ? "checked" : ""}>
                </label>
                <button class="account-select-btn" data-id="${account.id}">
                    <span class="account-sequence">${pageStart + index + 1}</span>
                    <span class="account-avatar">${escapeHtml((account.email || account.name || "A").slice(0, 1).toUpperCase())}</span>
                    <span class="account-copy">
                        <strong>${escapeHtml(account.email || account.name)}</strong>
                        <small>${escapeHtml(accountStatusText(account))}</small>
                        ${account.organization_id ? `<small>Org ${escapeHtml(account.organization_id)}</small>` : ""}
                        ${account.last_checked_at ? `<small>检测 ${escapeHtml(account.last_checked_at)}</small>` : ""}
                    </span>
                    <span class="account-dot ${account.has_org ? "ready" : ""}"></span>
                </button>
                <button class="account-inline-delete" data-id="${account.id}" title="删除母号" aria-label="删除母号">×</button>
            </div>
        `).join("");
        updateAccountPagination();
        updateAccountBulkSelection();
    }

    function updateAccountPagination() {
        const totalPages = Math.max(1, Math.ceil(accounts.length / accountPageSize));
        accountPageLabel.textContent = `第 ${accountPage + 1} / ${totalPages} 页 · 共 ${accounts.length} 个`;
        accountPrevBtn.disabled = accountPage <= 0;
        accountNextBtn.disabled = accountPage >= totalPages - 1;
    }

    async function loadAccounts(preferredId = "") {
        accounts = await api("/api/adobe-accounts");
        const preferredIndex = accounts.findIndex(item => item.id === preferredId);
        if (preferredIndex >= 0) accountPage = Math.floor(preferredIndex / accountPageSize);
        const currentStillExists = accounts.some(item => item.id === selectedId);
        const nextId = preferredId || (currentStillExists ? selectedId : accounts[accountPage * accountPageSize]?.id) || accounts[0]?.id || "";
        setSelected(accounts.some(item => item.id === nextId) ? nextId : "");
    }

    function renderResults(title, results) {
        const time = new Date().toLocaleTimeString();
        const rows = results.map(result => `
            <div class="operation-row ${result.ok ? "success" : "failure"}">
                <span class="operation-mark">${result.ok ? "✓" : "×"}</span>
                <span>
                    <strong>${escapeHtml(result.email || title)}</strong>
                    <small>${escapeHtml(result.message || "")}</small>
                    ${Array.isArray(result.logs) && result.logs.length ? `
                        <pre class="operation-detail">${result.logs.map(line => escapeHtml(line)).join("\n")}</pre>
                    ` : ""}
                </span>
                <time>${time}</time>
            </div>
        `).join("");
        if (logEl.querySelector(".empty-hint")) logEl.innerHTML = "";
        logEl.insertAdjacentHTML("afterbegin", rows);
    }

    function updateMemberPagination() {
        memberPageLabel.textContent = `第 ${memberPage + 1} 页`;
        memberPrevBtn.disabled = memberPage <= 0;
        memberNextBtn.disabled = !memberHasMore;
    }

    function updateMemberSelection() {
        const selectable = [...memberRows.querySelectorAll(".member-check:not(:disabled)")];
        const checked = selectable.filter(input => input.checked);
        removeSelectedBtn.disabled = checked.length === 0;
        selectAllMembers.disabled = selectable.length === 0;
        selectAllMembers.checked = selectable.length > 0 && checked.length === selectable.length;
        selectAllMembers.indeterminate = checked.length > 0 && checked.length < selectable.length;
    }

    async function loadMembers() {
        if (!selectedId) return;
        refreshMembersBtn.disabled = true;
        refreshMembersBtn.textContent = "读取中...";
        memberRows.innerHTML = '<tr><td colspan="6" class="empty-state">正在读取成员...</td></tr>';
        try {
            const query = new URLSearchParams({page: memberPage, page_size: 20, search: memberSearch.value.trim()});
            const data = await api(`/api/adobe-accounts/${selectedId}/members?${query}`);
            memberHasMore = data.has_more;
            memberSummary.textContent = `组织 ${data.organization_id || "-"} · 本页 ${data.members.length} 名成员`;
            if (!data.members.length) {
                memberRows.innerHTML = '<tr><td colspan="6" class="empty-state">没有匹配成员</td></tr>';
            } else {
                memberRows.innerHTML = data.members.map(member => `
                    <tr>
                        <td><input class="member-check" type="checkbox" data-email="${escapeHtml(member.email)}" ${member.removable && !member.protected ? "" : "disabled"}></td>
                        <td><strong>${escapeHtml([member.first_name, member.last_name].filter(Boolean).join(" ") || member.email)}</strong><small>${escapeHtml(member.email)}</small></td>
                        <td>${escapeHtml(member.type || "-")}</td>
                        <td>${escapeHtml(member.products)}</td>
                        <td><span class="member-status">${escapeHtml(member.account_status || "-")}</span></td>
                        <td>${member.protected ? '<span class="protected-account-badge">母号</span>' : `<button class="btn-sm danger queue-remove-btn" data-email="${escapeHtml(member.email)}" ${member.removable ? "" : "disabled"}>移除</button>`}</td>
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
        emailInput.focus();
        showStatus("正在新增母号。", true);
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
                    name: emailInput.value,
                    email: emailInput.value,
                    hotmail_password: hotmailPasswordInput.value,
                    adobe_password: adobePasswordInput.value,
                    client_id: clientIdInput.value,
                    refresh_token: refreshTokenInput.value,
                }),
            });
            await loadAccounts(account.id);
            showStatus("母号已保存。", true);
        } catch (error) {
            showStatus(error.message, false);
        } finally {
            button.disabled = false;
            button.textContent = "保存母号";
        }
    });

    async function runBatchImport(onDuplicate) {
        try {
            const result = await api("/api/adobe-accounts/batch-import", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({content: batchContent.value, on_duplicate: onDuplicate}),
            });
            await loadAccounts();
            showStatus(`导入完成：新增 ${result.created}，更新 ${result.updated}，跳过 ${result.skipped}，失败 ${result.failed}`, result.failed === 0);
        } catch (error) {
            showStatus(error.message, false);
        }
    }

    document.getElementById("batch-import-btn").addEventListener("click", () => runBatchImport("skip"));
    document.getElementById("batch-overwrite-btn").addEventListener("click", () => runBatchImport("overwrite"));

    testBtn.addEventListener("click", async () => {
        testBtn.disabled = true;
        testBtn.textContent = "检测中...";
        try {
            const result = await api(`/api/adobe-accounts/${selectedId}/test`, {method: "POST"});
            showStatus(result.message, true);
            renderResults("协议检测", [{ok: true, message: result.message, logs: result.logs || []}]);
            await loadAccounts(selectedId);
        } catch (error) {
            showStatus(error.message, false);
            renderResults("协议检测", [{ok: false, message: error.message, logs: error.logs || []}]);
        } finally {
            testBtn.disabled = false;
            testBtn.textContent = "协议检测";
        }
    });

    async function deleteAccount(accountId) {
        const account = accounts.find(item => item.id === accountId);
        if (!account || !confirm(`确定删除母号 ${account.email || account.name} 吗？`)) return;
        try {
            await api(`/api/adobe-accounts/${accountId}`, {method: "DELETE"});
            if (accountId === selectedId) selectedId = "";
            await loadAccounts(selectedId);
            showStatus("母号已删除。", true);
        } catch (error) {
            showStatus(error.message, false);
        }
    }

    async function deleteSelectedAccounts() {
        const ids = [...selectedAccountIds];
        if (!ids.length) return;
        if (!confirm(`确定删除选中的 ${ids.length} 个母号吗？`)) return;
        deleteSelectedAccountsBtn.disabled = true;
        deleteSelectedAccountsBtn.textContent = "删除中...";
        try {
            const result = await api("/api/adobe-accounts/delete", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({ids}),
            });
            if (ids.includes(selectedId)) selectedId = "";
            selectedAccountIds.clear();
            await loadAccounts(selectedId);
            showStatus(`已删除 ${result.deleted || 0} 个母号`, true);
        } catch (error) {
            showStatus(error.message, false);
            updateAccountBulkSelection();
        }
    }

    async function testSelectedAccounts() {
        const ids = [...selectedAccountIds];
        if (!ids.length) return;
        testSelectedAccountsBtn.disabled = true;
        testSelectedAccountsBtn.textContent = "检测中...";
        try {
            const result = await api("/api/adobe-accounts/test", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({ids}),
            });
            renderResults("批量协议检测", result.results || []);
            showStatus(`批量检测完成：成功 ${result.success || 0}，失败 ${result.failed || 0}`, (result.failed || 0) === 0);
            await loadAccounts(selectedId);
        } catch (error) {
            showStatus(error.message, false);
            renderResults("批量协议检测", error.results || [{ok: false, message: error.message, logs: error.logs || []}]);
            updateAccountBulkSelection();
        }
    }

    listEl.addEventListener("click", event => {
        if (event.target.closest(".account-batch-check-wrap")) {
            event.stopPropagation();
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

    listEl.addEventListener("change", event => {
        const checkbox = event.target.closest(".account-batch-check");
        if (!checkbox) return;
        if (checkbox.checked) {
            selectedAccountIds.add(checkbox.dataset.id);
        } else {
            selectedAccountIds.delete(checkbox.dataset.id);
        }
        updateAccountBulkSelection();
    });

    selectAllAccounts?.addEventListener("change", () => {
        pageAccountIds().forEach(id => {
            if (selectAllAccounts.checked) {
                selectedAccountIds.add(id);
            } else {
                selectedAccountIds.delete(id);
            }
        });
        renderAccounts();
    });
    testSelectedAccountsBtn?.addEventListener("click", testSelectedAccounts);
    deleteSelectedAccountsBtn?.addEventListener("click", deleteSelectedAccounts);
    deleteBtn.addEventListener("click", () => deleteAccount(selectedId));
    accountPrevBtn.addEventListener("click", () => { accountPage = Math.max(0, accountPage - 1); renderAccounts(); });
    accountNextBtn.addEventListener("click", () => {
        const totalPages = Math.max(1, Math.ceil(accounts.length / accountPageSize));
        accountPage = Math.min(totalPages - 1, accountPage + 1);
        renderAccounts();
    });

    async function runTeamAction(kind, suppliedEmails = null) {
        const isRemove = kind === "remove";
        const button = isRemove ? removeSelectedBtn : inviteBtn;
        const textarea = document.getElementById("invite-emails");
        const emails = suppliedEmails || parseEmails(textarea.value);
        if (!emails.length) {
            renderResults("输入检查", [{ok: false, message: "请至少填写一个邮箱"}]);
            return false;
        }
        if (isRemove && !confirm(`确定从组织移除 ${emails.length} 个成员吗？`)) return false;
        button.disabled = true;
        button.textContent = isRemove ? "移除中..." : "授权中...";
        try {
            const result = await api(`/api/adobe-team/${kind === "invite" ? "invite" : "remove"}`, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({account_id: selectedId, emails}),
            });
            renderResults(isRemove ? "移除成员" : "授权成员", result.results);
            return true;
        } catch (error) {
            renderResults("执行失败", [{ok: false, message: error.message}]);
            return false;
        } finally {
            button.disabled = false;
            button.textContent = isRemove ? "移除选中" : "发送授权";
        }
    }

    inviteBtn.addEventListener("click", () => runTeamAction("invite"));
    removeSelectedBtn.addEventListener("click", async () => {
        const emails = [...memberRows.querySelectorAll(".member-check:checked")].map(input => input.dataset.email);
        if (await runTeamAction("remove", emails)) await loadMembers();
    });
    selectAllMembers.addEventListener("change", () => {
        memberRows.querySelectorAll(".member-check:not(:disabled)").forEach(input => {
            input.checked = selectAllMembers.checked;
        });
        updateMemberSelection();
    });
    refreshMembersBtn.addEventListener("click", () => { memberPage = 0; loadMembers(); });
    memberSearch.addEventListener("keydown", event => {
        if (event.key === "Enter") {
            memberPage = 0;
            loadMembers();
        }
    });
    memberPrevBtn.addEventListener("click", () => { memberPage = Math.max(0, memberPage - 1); loadMembers(); });
    memberNextBtn.addEventListener("click", () => { memberPage += 1; loadMembers(); });
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
        logEl.innerHTML = '<div class="empty-hint">等待操作</div>';
    });

    loadAccounts().catch(error => showStatus(error.message, false));
});
