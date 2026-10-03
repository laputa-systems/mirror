import { api, button, el, input, setMsg, wireCopy } from "./common.ts";

// Server-sent WebAuthn options: the W3C option dictionaries with every
// binary field base64url-encoded as a string.
type Base64url = string;
type CreationOptionsJson = Omit<PublicKeyCredentialCreationOptions, "challenge" | "user" | "excludeCredentials"> & {
    challenge: Base64url;
    user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: Base64url };
};
type RequestOptionsJson = Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
    challenge: Base64url;
    allowCredentials: (Omit<PublicKeyCredentialDescriptor, "id"> & { id: Base64url })[];
};

type OptionsResponse<O> = { session_id: string; options: O };
type TokenResponse = { token: string };

// Base64url helpers use btoa/atob: Uint8Array.toBase64/fromBase64 are too new for our browser baseline.
const toB64url = (buf: ArrayBuffer) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");

const fromB64url = (s: string) => {
    const b64 = s.replaceAll("-", "+").replaceAll("_", "/");
    return Uint8Array.from(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
};

const decodeCreation = (o: CreationOptionsJson): PublicKeyCredentialCreationOptions => ({
    ...o,
    challenge: fromB64url(o.challenge),
    user: { ...o.user, id: fromB64url(o.user.id) },
});

const decodeRequest = (o: RequestOptionsJson): PublicKeyCredentialRequestOptions => ({
    ...o,
    challenge: fromB64url(o.challenge),
    allowCredentials: o.allowCredentials.map((c) => ({ ...c, id: fromB64url(c.id) })),
});

const encodeCredential = (cred: PublicKeyCredential) => {
    const r = cred.response;
    return {
        id: cred.id,
        rawId: toB64url(cred.rawId),
        type: cred.type,
        response: {
            attestationObject: r instanceof AuthenticatorAttestationResponse ? toB64url(r.attestationObject) : null,
            authenticatorData: r instanceof AuthenticatorAssertionResponse ? toB64url(r.authenticatorData) : null,
            clientDataJSON: toB64url(r.clientDataJSON),
            signature: r instanceof AuthenticatorAssertionResponse ? toB64url(r.signature) : null,
        },
    };
};

const asPublicKeyCredential = (c: Credential | null) => {
    if (!(c instanceof PublicKeyCredential)) throw new Error("No passkey returned");
    return c;
};

// Exactly one of the page's sections is visible at a time.
function showSection(id: "section-signin" | "section-register" | "section-token") {
    for (const section of document.querySelectorAll("section")) section.hidden = section.id !== id;
}

function showToken(token: string) {
    showSection("section-token");
    el("token-value").textContent = token;
}

// Runs one WebAuthn ceremony against `/auth/<kind>/{options,verify}`.
// `ceremony` is the browser call; the server session ties the two requests together.
async function runCeremony<O>(
    kind: "register" | "authenticate",
    msgId: string,
    btnId: string,
    optionsBody: object,
    ceremony: (options: O) => Promise<Credential | null>,
    failure: string,
): Promise<{ status: number } | undefined> {
    const submit = button(btnId);
    setMsg(msgId, "Requesting...");
    submit.disabled = true;

    const opts = await api<OptionsResponse<O>>(`/auth/${kind}/options`, optionsBody);
    if (!opts.ok || !opts.data.options) {
        submit.disabled = false;
        if (opts.status !== 404) setMsg(msgId, opts.data.error || "Error", true);
        return { status: opts.status };
    }

    try {
        setMsg(msgId, "Waiting for passkey...");
        const cred = asPublicKeyCredential(await ceremony(opts.data.options));
        setMsg(msgId, "Verifying...");
        const verified = await api<TokenResponse>(`/auth/${kind}/verify`, {
            session_id: opts.data.session_id,
            credential: encodeCredential(cred),
        });
        if (!verified.ok || !verified.data.token) throw new Error(verified.data.error || failure);
        showToken(verified.data.token);
    } catch (e) {
        setMsg(msgId, e instanceof Error ? e.message : String(e), true);
        submit.disabled = false;
    }
    return undefined;
}

el("signin-btn").addEventListener("click", async () => {
    const failed = await runCeremony<RequestOptionsJson>(
        "authenticate", "signin-msg", "signin-btn", {},
        (o) => navigator.credentials.get({ publicKey: decodeRequest(o) }),
        "Verification failed",
    );
    // 404 means no passkey is registered yet: offer registration instead.
    if (failed?.status === 404) {
        showSection("section-register");
    }
});

el("register-btn").addEventListener("click", async () => {
    const username = input("username-input").value.trim();
    if (!username) return setMsg("register-msg", "Enter username", true);
    await runCeremony<CreationOptionsJson>(
        "register", "register-msg", "register-btn", { username },
        (o) => navigator.credentials.create({ publicKey: decodeCreation(o) }),
        "Registration failed",
    );
});

el("go-register").addEventListener("click", (e) => {
    e.preventDefault();
    showSection("section-register");
});

el("back-btn").addEventListener("click", () => showSection("section-signin"));

wireCopy("copy-btn", "token-value");
