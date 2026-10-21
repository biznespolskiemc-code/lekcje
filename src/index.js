
const COOKIE_NAME = "__Host-lekcje_session";
const SESSION_DURATION = 8 * 60 * 60;
const encoder = new TextEncoder();

function json(data, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            ...extraHeaders
        }
    });
}

function equalStrings(a, b) {
    if (typeof a !== "string" || typeof b !== "string") {
        return false;
    }

    if (a.length !== b.length) {
        return false;
    }

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return difference === 0;
}

async function signSession(timestamp, secret) {
    if (typeof secret !== "string" || secret.length < 32) {
        throw new Error("Invalid session secret");
    }

    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(timestamp)
    );

    return Array.from(new Uint8Array(signature))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

async function isAuthenticated(request, env) {
    try {
        const cookieHeader = request.headers.get("Cookie") || "";
        const escapedName = COOKIE_NAME.replace(
            /[.*+?^${}()|[\]\\]/g,
            "\\$&"
        );

        const cookie = cookieHeader.match(
            new RegExp("(?:^|;\\s*)" + escapedName + "=([^;]+)")
        );

        if (!cookie) return false;

        const session = cookie[1].match(
            /^(\d{10})\.([a-f0-9]{64})$/
        );

        if (!session) return false;

        const timestamp = session[1];
        const suppliedSignature = session[2];

        const issuedAt = Number(timestamp);
        const now = Math.floor(Date.now() / 1000);

        if (
            !Number.isSafeInteger(issuedAt) ||
            issuedAt > now + 60 ||
            now - issuedAt >= SESSION_DURATION
        ) {
            return false;
        }

        const expectedSignature = await signSession(
            timestamp,
            env.SESSION_SECRET
        );

        return equalStrings(
            suppliedSignature,
            expectedSignature
        );
    } catch {
        return false;
    }
}

function hasValidOrigin(request, url) {
    return request.headers.get("Origin") === url.origin;
}

async function handleLogin(request, env, url) {
    if (request.method !== "POST") {
        return json({ error: "method_not_allowed" }, 405, {
            Allow: "POST"
        });
    }

    if (!hasValidOrigin(request, url)) {
        return json({ error: "forbidden" }, 403);
    }

    if (!env.LEKCJE_PASSWORD || !env.SESSION_SECRET) {
        return json({ error: "server_configuration_error" }, 500);
    }

    let body;

    try {
        const raw = await request.text();

        if (raw.length > 4096) {
            return json({ error: "request_too_large" }, 413);
        }

        body = JSON.parse(raw);
    } catch {
        return json({ error: "invalid_request" }, 400);
    }

    const password = body?.password;

    if (
        typeof password !== "string" ||
        password.length === 0 ||
        password.length > 1024
    ) {
        return json({ error: "invalid_password" }, 400);
    }

    if (!equalStrings(password, env.LEKCJE_PASSWORD)) {
        return json({ error: "invalid_credentials" }, 401);
    }

    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = await signSession(
        timestamp,
        env.SESSION_SECRET
    );

    const cookie =
        `${COOKIE_NAME}=${timestamp}.${signature}; ` +
        `Path=/; Max-Age=${SESSION_DURATION}; ` +
        "HttpOnly; Secure; SameSite=Lax";

    return json(
        { ok: true },
        200,
        { "Set-Cookie": cookie }
    );
}

async function handleAuth(request, env) {
    if (request.method !== "GET") {
        return json({ error: "method_not_allowed" }, 405, {
            Allow: "GET"
        });
    }

    if (!(await isAuthenticated(request, env))) {
        return json({ error: "login_required" }, 401);
    }

    return json({ authenticated: true });
}

async function handleLogout(request, url) {
    if (request.method !== "POST") {
        return json({ error: "method_not_allowed" }, 405, {
            Allow: "POST"
        });
    }

    if (!hasValidOrigin(request, url)) {
        return json({ error: "forbidden" }, 403);
    }

    return json(
        { ok: true },
        200,
        {
            "Set-Cookie":
                `${COOKIE_NAME}=; Path=/; Max-Age=0; ` +
                "HttpOnly; Secure; SameSite=Lax"
        }
    );
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        let path;

        try {
            path = decodeURIComponent(url.pathname)
                .replace(/\/+$/, "")
                .toLowerCase() || "/";
        } catch {
            return new Response("Nieprawidłowy adres.", {
                status: 400
            });
        }

        // Endpointy logowania.
        if (path === "/api/login") {
            return handleLogin(request, env, url);
        }

        if (path === "/api/auth") {
            return handleAuth(request, env);
        }

        if (path === "/api/logout") {
            return handleLogout(request, url);
        }

        if (path.startsWith("/api/")) {
            return json({ error: "not_found" }, 404);
        }

        // Publiczna pozostaje tylko strona logowania.
        const isLoginPage =
            path === "/" || path === "/index.html";

        // Każda pozostała strona HTML wymaga sesji.
        const isHtmlPage = path.endsWith(".html");

        if (
            isHtmlPage &&
            !isLoginPage &&
            !(await isAuthenticated(request, env))
        ) {
            const loginUrl = new URL("/index.html", url.origin);

            loginUrl.searchParams.set("reason", "expired");
            loginUrl.searchParams.set(
                "next",
                url.pathname + url.search
            );

            return new Response(null, {
                status: 302,
                headers: {
                    Location: loginUrl.toString(),
                    "Cache-Control": "no-store"
                }
            });
        }

        // Pliki CSS, grafik i HTML pobieramy z zasobów statycznych.
        const response = await env.ASSETS.fetch(request);

        // Chroniony HTML nie powinien być przechowywany w pamięci
        // podręcznej przeglądarki.
        if (isHtmlPage && !isLoginPage && response.ok) {
            const headers = new Headers(response.headers);

            headers.set("Cache-Control", "private, no-store");
            headers.set("Pragma", "no-cache");

            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers
            });
        }

        return response;
    }
};
