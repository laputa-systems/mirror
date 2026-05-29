(() => {
  // static/js/auth.ts
  var toB64url = (buf) => {
    const bytes = new Uint8Array(buf);
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  };
  var fromB64url = (s) => {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + (4 - s.length % 4) % 4, "="));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  };
  var decodeOptions = (opt) => ({
    ...opt,
    challenge: fromB64url(opt.challenge),
    user: opt.user ? { ...opt.user, id: fromB64url(opt.user.id) } : void 0,
    excludeCredentials: (opt.excludeCredentials || []).map((c) => ({ ...c, id: fromB64url(c.id) })),
    allowCredentials: (opt.allowCredentials || []).map((c) => ({ ...c, id: fromB64url(c.id) }))
  });
  var encodeCred = (cred) => ({
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: cred.response.attestationObject ? toB64url(cred.response.attestationObject) : null,
      authenticatorData: cred.response.authenticatorData ? toB64url(cred.response.authenticatorData) : null,
      clientDataJSON: toB64url(cred.response.clientDataJSON),
      signature: cred.response.signature ? toB64url(cred.response.signature) : null
    }
  });
  var ui = {
    setMsg: (id, text, isErr = false) => {
      const el = document.getElementById(id);
      el.textContent = text;
      el.className = "msg" + (isErr ? " err" : "");
    },
    setDisabled: (id, v) => {
      document.getElementById(id).disabled = v;
    },
    showToken: (token) => {
      document.getElementById("section-signin").style.display = "none";
      document.getElementById("section-register").style.display = "none";
      document.getElementById("section-token").style.display = "block";
      document.getElementById("token-value").textContent = token;
    }
  };
  async function api(url, body = {}) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  }
  async function doAuthenticate() {
    ui.setMsg("signin-msg", "Requesting...", false);
    ui.setDisabled("signin-btn", true);
    const { ok, status, data } = await api("/auth/authenticate/options");
    if (!ok) {
      if (status === 404) {
        document.getElementById("section-signin").style.display = "none";
        document.getElementById("section-register").style.display = "block";
      } else {
        ui.setMsg("signin-msg", data.error || "Error", true);
      }
      ui.setDisabled("signin-btn", false);
      return;
    }
    try {
      ui.setMsg("signin-msg", "Waiting for passkey...", false);
      const cred = await navigator.credentials.get({ publicKey: decodeOptions(data.options) });
      ui.setMsg("signin-msg", "Verifying...", false);
      const { ok: vOk, data: vData } = await api("/auth/authenticate/verify", {
        session_id: data.session_id,
        credential: encodeCred(cred)
      });
      if (!vOk) throw new Error(vData.error || "Verification failed");
      ui.showToken(vData.token);
    } catch (e) {
      ui.setMsg("signin-msg", e.message || String(e), true);
      ui.setDisabled("signin-btn", false);
    }
  }
  async function doRegister() {
    const username = document.getElementById("username-input").value.trim();
    if (!username) return ui.setMsg("register-msg", "Enter username", true);
    ui.setMsg("register-msg", "Requesting...", false);
    ui.setDisabled("register-btn", true);
    const { ok, status, data } = await api("/auth/register/options", { username });
    if (!ok) {
      ui.setMsg("register-msg", data.error || "Error", true);
      ui.setDisabled("register-btn", false);
      return;
    }
    try {
      ui.setMsg("register-msg", "Waiting for passkey...", false);
      const cred = await navigator.credentials.create({ publicKey: decodeOptions(data.options) });
      ui.setMsg("register-msg", "Verifying...", false);
      const { ok: vOk, data: vData } = await api("/auth/register/verify", {
        session_id: data.session_id,
        credential: encodeCred(cred)
      });
      if (!vOk) throw new Error(vData.error || "Registration failed");
      ui.showToken(vData.token);
    } catch (e) {
      ui.setMsg("register-msg", e.message || String(e), true);
      ui.setDisabled("register-btn", false);
    }
  }
  document.getElementById("signin-btn").addEventListener("click", doAuthenticate);
  document.getElementById("register-btn").addEventListener("click", doRegister);
  document.getElementById("back-btn").addEventListener("click", () => {
    document.getElementById("section-register").style.display = "none";
    document.getElementById("section-signin").style.display = "block";
  });
  document.getElementById("copy-btn").addEventListener("click", async () => {
    const token = document.getElementById("token-value").textContent;
    if (token) {
      await navigator.clipboard.writeText(token).catch(() => {
      });
      document.getElementById("copy-btn").textContent = "Copied!";
      setTimeout(() => {
        document.getElementById("copy-btn").textContent = "Copy";
      }, 2e3);
    }
  });
})();
