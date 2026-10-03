function byId<E extends HTMLElement>(id: string, kind: new () => E): E {
    const found = document.getElementById(id);
    if (!(found instanceof kind)) throw new Error(`#${id} is missing or not a ${kind.name}`);
    return found;
}

export const el = (id: string) => byId(id, HTMLElement);
export const button = (id: string) => byId(id, HTMLButtonElement);
export const input = (id: string) => byId(id, HTMLInputElement);
export const select = (id: string) => byId(id, HTMLSelectElement);

export function setMsg(id: string, text: string, isErr = false) {
    const e = el(id);
    e.textContent = text;
    e.className = "msg" + (isErr ? " err" : "");
}

export function show(id: string, display: "block" | "none") {
    el(id).style.display = display;
}

// Error bodies are `{ "error": string }`; the success shape `T` is the caller's
// claim about the endpoint, not validated here.
export type ApiResult<T> = { ok: boolean; status: number; data: Partial<T> & { error?: string } };

export async function api<T>(url: string, body: object = {}): Promise<ApiResult<T>> {
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const data: ApiResult<T>["data"] = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}

// Shared by both pages: copy `sourceId`'s text and flash the button label.
export function wireCopy(buttonId: string, sourceId: string) {
    el(buttonId).addEventListener("click", async () => {
        const text = el(sourceId).textContent;
        if (!text) return;
        await navigator.clipboard.writeText(text).catch(() => {});
        el(buttonId).textContent = "Copied!";
        setTimeout(() => { el(buttonId).textContent = "Copy"; }, 2000);
    });
}
