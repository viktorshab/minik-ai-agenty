import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

const workerPath = new URL("../src/worker.js", import.meta.url);
const worker = (await import(workerPath.href)).default;

// Простейшая замена D1 на одну строку.
function fakeDB() {
  let row = null;
  return {
    get row() { return row; },
    prepare(sql) {
      return { bind(...a) { return {
        async run() { if (sql.startsWith("INSERT")) row = { iv: a[1], ciphertext: a[2], username: a[3], updated_at: a[4] }; if (sql.startsWith("DELETE")) row = null; },
        async first() { return row; }
      }; } };
    }
  };
}
const key = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("base64");
const TOKEN = "apify_api_" + "x".repeat(30);
const calls = [];
globalThis.fetch = async (url, init) => {
  calls.push({ url: String(url), init });
  const auth = new Headers(init.headers).get("authorization");
  if (String(url).includes("users/me")) return auth === `Bearer ${TOKEN}` ? Response.json({ data: { username: "student1" } }) : new Response("no", { status: 401 });
  if (auth !== `Bearer ${TOKEN}`) return new Response("unauth", { status: 401, headers: { "www-authenticate": "Bearer resource_metadata=x" } });
  return new Response('{"jsonrpc":"2.0","id":1,"result":{}}', { headers: { "content-type": "application/json", "mcp-session-id": "s1", "set-cookie": "a=b" } });
};
const env = { DB: fakeDB(), CREDENTIALS_KEY: key };
const H = { "oai-authenticated-user-id": "u1" };
const req = (path, o = {}) => new Request("https://my.chatgpt.site" + path, { ...o, headers: { ...H, ...(o.headers || {}) } });
const rpc = JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/list" });

test("без входа 401", async () => {
  const r = await worker.fetch(new Request("https://my.chatgpt.site/mcp", { method: "POST", body: rpc }), env);
  assert.equal(r.status, 401);
});
test("без ключа /mcp отвечает понятной ошибкой с id", async () => {
  const r = await worker.fetch(req("/mcp", { method: "POST", body: rpc, headers: { "content-type": "application/json" } }), env);
  const j = await r.json();
  assert.equal(j.id, 7); assert.match(j.error.message, /Ключ Apify не сохранён/);
});
test("api/key без x-panel запрещён", async () => {
  const r = await worker.fetch(req("/api/key", { method: "POST", body: JSON.stringify({ token: TOKEN }) }), env);
  assert.equal(r.status, 403);
});
test("чужой Origin запрещён", async () => {
  const r = await worker.fetch(req("/api/key", { method: "POST", body: JSON.stringify({ token: TOKEN }), headers: { "x-panel": "1", origin: "https://evil.example" } }), env);
  assert.equal(r.status, 403);
});
test("неверный ключ не сохраняется", async () => {
  const r = await worker.fetch(req("/api/key", { method: "POST", body: JSON.stringify({ token: "apify_api_" + "y".repeat(30) }), headers: { "x-panel": "1" } }), env);
  assert.equal(r.status, 400); assert.equal(env.DB.row, null);
});
test("верный ключ сохраняется зашифрованным и не возвращается", async () => {
  const r = await worker.fetch(req("/api/key", { method: "POST", body: JSON.stringify({ token: TOKEN }), headers: { "x-panel": "1" } }), env);
  const t = await r.text();
  assert.equal(r.status, 200); assert.ok(!t.includes(TOKEN)); assert.match(t, /student1/);
  assert.ok(!JSON.stringify(env.DB.row).includes(TOKEN));
});
test("статус показывает логин без ключа", async () => {
  const r = await worker.fetch(req("/api/key", { headers: { "x-panel": "1" } }), env);
  const j = await r.json(); assert.equal(j.connected, true); assert.equal(j.username, "student1");
});
test("/mcp пересылает с Bearer, redirect manual, без set-cookie", async () => {
  calls.length = 0;
  const r = await worker.fetch(req("/mcp", { method: "POST", body: rpc, headers: { "content-type": "application/json", "mcp-protocol-version": "2025-06-18", cookie: "c=1" } }), env);
  assert.equal(r.status, 200);
  const c = calls.at(-1); const h = new Headers(c.init.headers);
  assert.match(c.url, /^https:\/\/mcp\.apify\.com\//);
  assert.equal(c.init.redirect, "manual"); assert.equal(h.get("authorization"), `Bearer ${TOKEN}`);
  assert.equal(h.get("cookie"), null); assert.equal(h.get("oai-authenticated-user-id"), null);
  assert.equal(r.headers.get("set-cookie"), null); assert.equal(r.headers.get("mcp-session-id"), "s1");
});
test("страница без ключа в HTML и с CSP", async () => {
  const r = await worker.fetch(req("/"), env);
  const t = await r.text();
  assert.ok(r.headers.get("content-security-policy").includes("nonce-")); assert.ok(!t.includes(TOKEN));
});
test("удаление ключа", async () => {
  const r = await worker.fetch(req("/api/key", { method: "DELETE", headers: { "x-panel": "1" } }), env);
  assert.equal((await r.json()).connected, false); assert.equal(env.DB.row, null);
});
test("401 от Apify не пропускает WWW-Authenticate", async () => {
  // сохраняем ключ, затем подменяем ответ upstream на 401
  await worker.fetch(req("/api/key", { method: "POST", body: JSON.stringify({ token: TOKEN }), headers: { "x-panel": "1" } }), env);
  const orig = globalThis.fetch;
  globalThis.fetch = async () => new Response("x", { status: 401, headers: { "www-authenticate": "Bearer" } });
  const r = await worker.fetch(req("/mcp", { method: "POST", body: rpc }), env);
  globalThis.fetch = orig;
  assert.equal(r.headers.get("www-authenticate"), null);
  assert.match((await r.json()).error.message, /не принял ключ/);
});
