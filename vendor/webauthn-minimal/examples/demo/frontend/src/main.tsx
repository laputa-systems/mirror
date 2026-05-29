import { h, render } from 'preact';
import { useState, useEffect } from 'preact/hooks';
// We only need these if we want to type the API responses
import type { 
    PublicKeyCredentialCreationOptions as ServerCreationOptions, 
    PublicKeyCredentialRequestOptions as ServerRequestOptions 
} from './types';

const toB64url = (buf: ArrayBuffer) => {
    const bytes = new Uint8Array(buf);
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
};

const fromB64url = (s: string) => {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + (4 - s.length % 4) % 4, "="));
    return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
};

const decodeRegOptions = (opt: any) => ({
    ...opt,
    challenge: fromB64url(opt.challenge),
    user: opt.user ? { ...opt.user, id: fromB64url(opt.user.id) } : undefined,
    excludeCredentials: (opt.excludeCredentials || []).map((c: any) => ({ ...c, id: fromB64url(c.id) })),
    allowCredentials: (opt.allowCredentials || []).map((c: any) => ({ ...c, id: fromB64url(c.id) })),
});

const decodeAuthOptions = (opt: any) => ({
    ...opt,
    challenge: fromB64url(opt.challenge),
    allowCredentials: (opt.allowCredentials || []).map((c: any) => ({ ...c, id: fromB64url(c.id) })),
});

const encodeCred = (cred: PublicKeyCredential) => {
    const resp = cred.response as any;
    return {
        id: cred.id,
        rawId: toB64url(cred.rawId),
        type: cred.type,
        response: {
            attestationObject: resp.attestationObject ? toB64url(resp.attestationObject) : null,
            authenticatorData: resp.authenticatorData ? toB64url(resp.authenticatorData) : null,
            clientDataJSON: toB64url(resp.clientDataJSON),
            signature: resp.signature ? toB64url(resp.signature) : null,
        },
    };
};

async function api(url: string, body: any = {}) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}

function App() {
    const [view, setView] = useState<'signin' | 'register' | 'token'>('register');
    const [username, setUsername] = useState('');
    const [token, setToken] = useState('');
    const [msg, setMsg] = useState({ text: '', isErr: false });
    const [loading, setLoading] = useState(false);
    const [copyText, setCopyText] = useState('Copy');

    useEffect(() => {
        if (localStorage.getItem("has-passkey") === "true") {
            setView('signin');
        }
    }, []);

    const doAuthenticate = async () => {
        setMsg({ text: 'Requesting...', isErr: false });
        setLoading(true);

        const { ok, status, data } = await api("/auth/authenticate/options");
        if (!ok) {
            if (status === 404) {
                setView('register');
            } else {
                setMsg({ text: data.error || "Error", isErr: true });
            }
            setLoading(false);
            return;
        }

        try {
            setMsg({ text: 'Waiting for passkey...', isErr: false });
            const cred = await navigator.credentials.get({ publicKey: decodeAuthOptions(data.options) }) as PublicKeyCredential | null;
            if (!cred) throw new Error("No credential returned");
            setMsg({ text: 'Verifying...', isErr: false });
            const { ok: vOk, data: vData } = await api("/auth/authenticate/verify", { 
                session_id: data.session_id, 
                credential: encodeCred(cred) 
            });
            if (!vOk) throw new Error(vData.error || "Verification failed");
            setToken(vData.token);
            setView('token');
        } catch (e: any) {
            setMsg({ text: e.message || String(e), isErr: true });
            setLoading(false);
        }
    };

    const doRegister = async () => {
        if (!username.trim()) {
            setMsg({ text: 'Enter username', isErr: true });
            return;
        }

        setMsg({ text: 'Requesting...', isErr: false });
        setLoading(true);

        const { ok, status, data } = await api("/auth/register/options", { username });
        if (!ok) {
            setMsg({ text: data.error || "Error", isErr: true });
            setLoading(false);
            return;
        }

        try {
            setMsg({ text: 'Waiting for passkey...', isErr: false });
            const cred = await navigator.credentials.create({ publicKey: decodeRegOptions(data.options) }) as PublicKeyCredential | null;
            if (!cred) throw new Error("No credential returned");
            setMsg({ text: 'Verifying...', isErr: false });
            const { ok: vOk, data: vData } = await api("/auth/register/verify", { 
                session_id: data.session_id, 
                credential: encodeCred(cred) 
            });
            if (!vOk) throw new Error(vData.error || "Registration failed");
            localStorage.setItem("has-passkey", "true");
            setToken(vData.token);
            setView('token');
        } catch (e: any) {
            setMsg({ text: e.message || String(e), isErr: true });
            setLoading(false);
        }
    };

    const copyToken = async () => {
        if (token) {
            await navigator.clipboard.writeText(token).catch(() => {});
            setCopyText('Copied!');
            setTimeout(() => setCopyText('Copy'), 2000);
        }
    };

    return (
        <div class="card">
            <h1>WebAuthn Minimal Demo</h1>

            {view === 'signin' && (
                <div>
                    <button class="btn btn-primary" onClick={doAuthenticate} disabled={loading}>
                        Sign in with passkey
                    </button>
                    <div class={`msg ${msg.isErr ? 'err' : ''}`}>{msg.text}</div>
                </div>
            )}

            {view === 'register' && (
                <div>
                    <h2 style={{fontSize: '1rem', marginBottom: '1rem', color: '#fff'}}>Register New Key</h2>
                    <div class="label">Username</div>
                    <input 
                        type="text" 
                        value={username} 
                        onInput={(e: any) => setUsername(e.target.value)} 
                        autocomplete="username"
                    />
                    <button class="btn btn-primary" onClick={doRegister} disabled={loading}>
                        Register
                    </button>
                    <div class={`msg ${msg.isErr ? 'err' : ''}`}>{msg.text}</div>
                </div>
            )}

            {view === 'token' && (
                <div>
                    <div class="msg" style={{color:'#a3e635', marginBottom: '.75rem'}}>✓ Authenticated</div>
                    <div>
                        <div class="label">SESSION_TOKEN</div>
                        <div class="token-box">{token}</div>
                        <button class="copy-btn" onClick={copyToken}>{copyText}</button>
                        <div class="msg">This token is shown once. Store it securely.</div>
                    </div>
                </div>
            )}
        </div>
    );
}

render(<App />, document.getElementById('app')!);
