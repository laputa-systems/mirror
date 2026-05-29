(() => {
  // static/js/settings.ts
  async function api(url, body = {}) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  }
  function setMsg(id, text, isErr = false) {
    const el = document.getElementById(id);
    el.textContent = text;
    el.className = "msg" + (isErr ? " err" : "");
  }
  document.getElementById("create-btn").addEventListener("click", async () => {
    const name = document.getElementById("name-input").value.trim();
    if (!name) {
      setMsg("create-msg", "Enter a name", true);
      return;
    }
    const ttl = document.getElementById("ttl-select").value;
    const body = { name, expires_days: ttl ? parseInt(ttl) : null };
    const btn = document.getElementById("create-btn");
    btn.disabled = true;
    setMsg("create-msg", "", false);
    const { ok, data } = await api("/auth/tokens", body);
    btn.disabled = false;
    if (!ok) {
      setMsg("create-msg", data.error || "Error", true);
      return;
    }
    document.getElementById("create-section").style.display = "none";
    document.getElementById("new-token-value").textContent = data.token;
    document.getElementById("new-token-section").style.display = "block";
  });
  document.getElementById("copy-btn").addEventListener("click", async () => {
    const token = document.getElementById("new-token-value").textContent;
    if (token) {
      await navigator.clipboard.writeText(token).catch(() => {
      });
      document.getElementById("copy-btn").textContent = "Copied!";
      setTimeout(() => {
        document.getElementById("copy-btn").textContent = "Copy";
      }, 2e3);
    }
  });
  document.querySelectorAll(".del-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const row = btn.closest("tr");
      if (!confirm("Delete token " + row.querySelector("td").textContent + "?")) return;
      const { ok } = await api("/auth/tokens/delete", { id: btn.dataset.id });
      if (ok) row.remove();
    });
  });
})();
