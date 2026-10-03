import { api, button, el, input, select, setMsg, setHidden, wireCopy } from "./common.ts";

el("create-btn").addEventListener("click", async () => {
    const name = input("name-input").value.trim();
    if (!name) return setMsg("create-msg", "Enter a name", true);
    const ttl = select("ttl-select").value;
    const body = { name, expires_days: ttl ? parseInt(ttl, 10) : null };

    const btn = button("create-btn");
    btn.disabled = true;
    setMsg("create-msg", "");

    const { ok, data } = await api<{ token: string }>("/auth/tokens", body);
    btn.disabled = false;
    if (!ok || !data.token) return setMsg("create-msg", data.error || "Error", true);

    setHidden("create-section", true);
    el("new-token-value").textContent = data.token;
    setHidden("new-token-section", false);
});

wireCopy("copy-btn", "new-token-value");

for (const btn of document.querySelectorAll<HTMLElement>(".del-btn")) {
    btn.addEventListener("click", async () => {
        const row = btn.closest("tr");
        if (!row) return;
        if (!confirm(`Delete token ${row.querySelector("td")?.textContent ?? ""}?`)) return;
        const { ok } = await api("/auth/tokens/delete", { id: btn.dataset["id"] });
        if (ok) row.remove();
    });
}
