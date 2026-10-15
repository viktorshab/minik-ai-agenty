// Личный мост ChatGPT -> Apify MCP для урока 4.1 мини-курса.
// Неофициальный проект, не связан с Apify. Работает на Sites в аккаунте ученика.
// Ключ Apify вводится только на странице этого сайта и хранится зашифрованным в D1.

const UPSTREAM = "https://mcp.apify.com/?tools=actors,docs,runs,storage";
const APIFY_ME = "https://api.apify.com/v2/users/me";
const KEY_ROW = "owner"; // сайт доступен только владельцу, ключ один
const MAX_BODY = 4096;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      // Платформа Sites пропускает сюда только вошедшего владельца и ставит этот заголовок.
      if (!request.headers.get("oai-authenticated-user-id")) return text("Нужен вход через ChatGPT", 401);

      const origin = request.headers.get("origin");
      if (url.pathname === "/mcp") {
        if (origin && origin !== "https://chatgpt.com" && origin !== url.origin) return text("Origin denied", 403);
        return await proxyMcp(request, env);
      }
      if (url.pathname === "/" && request.method === "GET") return panel();
      if (url.pathname === "/api/key") {
        // Только запросы со своей страницы: свой заголовок + свой Origin.
        if (request.headers.get("x-panel") !== "1" || (origin && origin !== url.origin)) {
          return json({ ok: false, error: "Запрос не со страницы плагина" }, 403);
        }
        if (request.method === "GET") return await keyStatus(env);
        if (request.method === "POST") return await saveKey(request, env);
        if (request.method === "DELETE") return await deleteKey(env);
      }
      return text("Not found", 404);
    } catch (err) {
      // Текст ошибки без ключей и без ответа Apify целиком.
      return json({ ok: false, error: "Ошибка сервера", detail: String(err?.message ?? err).slice(0, 200) }, 500);
    }
  }
};

// ---------- MCP: пересылка в Apify ----------

async function proxyMcp(request, env) {
  const body = request.method !== "GET" && request.method !== "HEAD" ? await request.arrayBuffer() : undefined;
  const id = rpcId(body);
  const token = await loadToken(env);
  if (!token) {
    return rpcError(id, "Ключ Apify не сохранён. Открой главную страницу этого плагина, вставь ключ и нажми «Проверить и сохранить».");
  }

  const headers = new Headers();
  for (const [name, value] of request.headers) {
    const n = name.toLowerCase();
    if (n.startsWith("mcp-") || n === "content-type" || n === "accept" || n === "last-event-id") headers.set(n, value);
  }
  headers.set("authorization", `Bearer ${token}`);

  // redirect: "error" в среде Sites падает с Invalid redirect value, поэтому "manual".
  const upstream = await fetch(UPSTREAM, { method: request.method, headers, body, redirect: "manual" });

  if (upstream.status === 401 || upstream.status === 403) {
    // Заголовок WWW-Authenticate от Apify не пропускаем: иначе ChatGPT уйдёт в чужой вход OAuth.
    return rpcError(id, "Apify не принял ключ. Открой страницу плагина и сохрани новый ключ из Apify Console.");
  }
  if (upstream.status >= 300 && upstream.status < 400) {
    return rpcError(id, `Apify ответил перенаправлением (${upstream.status}). Проверь адрес сервера.`);
  }

  const out = new Headers({ "cache-control": "no-store" });
  for (const [name, value] of upstream.headers) {
    const n = name.toLowerCase();
    if (n === "content-type" || n.startsWith("mcp-")) out.set(n, value);
  }
  return new Response(upstream.body, { status: upstream.status, headers: out });
}

function rpcId(body) {
  try { return body ? JSON.parse(new TextDecoder().decode(body))?.id ?? null : null; } catch { return null; }
}

function rpcError(id, message) {
  return json({ jsonrpc: "2.0", id, error: { code: -32001, message } });
}

// ---------- Ключ: проверка, шифрование, хранение ----------

async function saveKey(request, env) {
  const raw = await request.text();
  if (raw.length > MAX_BODY) return json({ ok: false, error: "Слишком длинный запрос" }, 413);
  let token;
  try { token = String(JSON.parse(raw).token ?? "").trim(); } catch { return json({ ok: false, error: "Неверный формат" }, 400); }
  if (!/^[A-Za-z0-9_-]{20,200}$/.test(token)) return json({ ok: false, error: "Это не похоже на ключ Apify" }, 400);

  const check = await fetch(APIFY_ME, { headers: { authorization: `Bearer ${token}` }, redirect: "manual" });
  if (!check.ok) return json({ ok: false, error: "Apify не принял ключ. Скопируй его ещё раз из Apify Console." }, 400);
  const me = await check.json().catch(() => ({}));
  const username = String(me?.data?.username ?? "аккаунт Apify").slice(0, 100);

  const { iv, data } = await encrypt(env, token);
  await env.DB.prepare(
    "INSERT INTO apify_key (id, iv, ciphertext, username, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) " +
    "ON CONFLICT(id) DO UPDATE SET iv = excluded.iv, ciphertext = excluded.ciphertext, username = excluded.username, updated_at = excluded.updated_at"
  ).bind(KEY_ROW, iv, data, username, Date.now()).run();
  return json({ ok: true, username });
}

async function keyStatus(env) {
  const row = await env.DB.prepare("SELECT username, updated_at FROM apify_key WHERE id = ?1").bind(KEY_ROW).first();
  return json(row ? { ok: true, connected: true, username: row.username, updated_at: row.updated_at } : { ok: true, connected: false });
}

async function deleteKey(env) {
  await env.DB.prepare("DELETE FROM apify_key WHERE id = ?1").bind(KEY_ROW).run();
  return json({ ok: true, connected: false });
}

async function loadToken(env) {
  const row = await env.DB.prepare("SELECT iv, ciphertext FROM apify_key WHERE id = ?1").bind(KEY_ROW).first();
  return row ? decrypt(env, row.iv, row.ciphertext) : null;
}

async function aesKey(env) {
  const raw = env.CREDENTIALS_KEY;
  if (!raw) throw new Error("Не настроен серверный секрет CREDENTIALS_KEY");
  const bytes = fromB64(raw);
  if (bytes.length !== 32) throw new Error("CREDENTIALS_KEY должен быть 32 случайных байта в base64");
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encrypt(env, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env), new TextEncoder().encode(plain));
  return { iv: toB64(iv), data: toB64(new Uint8Array(data)) };
}

async function decrypt(env, iv, data) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, await aesKey(env), fromB64(data));
  return new TextDecoder().decode(plain);
}

const toB64 = bytes => btoa(String.fromCharCode(...bytes));
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// ---------- Ответы и страница ----------

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" }
  });
}

function text(value, status) {
  return new Response(value, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
}

function panel() {
  const nonce = crypto.randomUUID();
  const html = `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Мой плагин Apify</title>
<style nonce="${nonce}">
body{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f6f8;color:#1d1d1f;margin:0;padding:24px}
main{max-width:520px;margin:0 auto;background:#fff;border-radius:16px;padding:24px;box-shadow:0 2px 16px #0001}
h1{font-size:22px;margin:0 0 8px}p{margin:8px 0}label{display:block;font-weight:600;margin-top:16px}
input{width:100%;box-sizing:border-box;font:inherit;padding:12px;border:1px solid #c7c7cc;border-radius:10px;margin-top:6px}
button{font:inherit;font-weight:600;padding:12px 18px;border:0;border-radius:10px;margin:12px 8px 0 0;cursor:pointer}
#save{background:#0088ff;color:#fff}#del{background:#eee;color:#1d1d1f}#st{margin-top:16px;font-weight:600}.small{font-size:14px;color:#6e6e73}
</style></head><body><main>
<h1>Мой плагин Apify</h1>
<p>Здесь ты один раз сохраняешь свой ключ Apify. Ключ уходит прямо на сервер этого сайта, хранится зашифрованным и в чат не попадает.</p>
<p class="small">Где взять ключ: apify.com, войди, слева Settings, вкладка API &amp; Integrations, скопируй Personal API token.</p>
<label for="tk">Ключ Apify</label>
<input id="tk" type="password" autocomplete="off" spellcheck="false" placeholder="apify_api_...">
<button id="save">Проверить и сохранить</button><button id="del">Удалить ключ</button>
<p id="st">Проверяю…</p>
<p class="small">Сохранил? Вернись в чат и напиши: «Ключ сохранён».</p>
</main>
<script nonce="${nonce}">
const st = document.getElementById("st"), tk = document.getElementById("tk");
async function call(method, body) {
  try {
    const r = await fetch("/api/key", { method, headers: { "content-type": "application/json", "x-panel": "1" }, body: body ? JSON.stringify(body) : undefined });
    return await r.json();
  } catch { return { ok: false, error: "Нет связи с сервером. Обнови страницу." }; }
}
function show(r) {
  if (!r.ok) { st.textContent = "Не получилось: " + (r.error || "ошибка"); st.style.color = "#c00"; return; }
  st.style.color = r.connected === false ? "#6e6e73" : "#1a7f37";
  st.textContent = r.connected === false ? "Ключ ещё не сохранён." : "Подключено: " + r.username;
}
document.getElementById("save").onclick = async () => {
  if (!tk.value.trim()) { show({ ok: false, error: "вставь ключ в поле" }); return; }
  st.textContent = "Проверяю ключ в Apify…"; st.style.color = "#6e6e73";
  const r = await call("POST", { token: tk.value.trim() }); tk.value = ""; show(r);
};
document.getElementById("del").onclick = async () => show(await call("DELETE"));
call("GET").then(show);
</script></body></html>`;
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
      "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
      "x-frame-options": "DENY", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff"
    }
  });
}
