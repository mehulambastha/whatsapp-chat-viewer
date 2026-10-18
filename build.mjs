#!/usr/bin/env node
// Builds a single, passphrase-locked HTML file from a WhatsApp chat export.
//
//   node build.mjs --in "Chat.zip" --pass "correct horse battery staple" [--out dist/chat.html]
//   node build.mjs --chat "DMs=dm.zip" --chat "Notes=notes.zip" --ask "Group" --pass "…"
//
// --ask "Label" adds a chat that is NOT stored in the file (e.g. a huge export with media);
// the page lists it and asks the reader to open that chat's .zip on their device.
//
// The chat is gzipped, then encrypted with AES-256-GCM using a key derived from the
// passphrase via PBKDF2-SHA256 (1,000,000 iterations by default). Nothing readable —
// not even the chat name — is left in the output; it unlocks in the browser.
// If --pass is omitted, CHAT_PASS is used, otherwise you are prompted (input hidden).

import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import readline from "node:readline";
import { webcrypto as crypto } from "node:crypto";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

function args(){
  const a = process.argv.slice(2), o = { items: [] };
  for (let i = 0; i < a.length; i++){
    const k = a[i];
    if (!k.startsWith("--")) continue;
    const key = k.slice(2), v = a[i + 1];
    const val = (v === undefined || v.startsWith("--")) ? true : (i++, v);
    if (key === "chat" || key === "ask" || key === "in") o.items.push({ key, val }); else o[key] = val;
  }
  return o;
}

function readChat(file){
  const buf = fs.readFileSync(file);
  if (buf[0] !== 0x50 || buf[1] !== 0x4b) return { name: path.basename(file), text: buf.toString("utf8") };   // not "PK": plain .txt
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let e = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50){ e = i; break; }
  if (e < 0) throw new Error("Not a valid zip file");
  let p = dv.getUint32(e + 16, true);
  for (let k = 0, n = dv.getUint16(e + 10, true); k < n; k++){
    const method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true);
    const nlen = dv.getUint16(p + 28, true), xlen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
    const off = dv.getUint32(p + 42, true), name = buf.subarray(p + 46, p + 46 + nlen).toString("utf8");
    if (/\.txt$/i.test(name)){
      const start = off + 30 + dv.getUint16(off + 26, true) + dv.getUint16(off + 28, true);
      const data = buf.subarray(start, start + csize);
      if (method !== 0 && method !== 8) throw new Error("Unsupported zip compression");
      return { name, text: (method === 8 ? zlib.inflateRawSync(data) : data).toString("utf8") };
    }
    p += 46 + nlen + xlen + clen;
  }
  throw new Error("No .txt chat file inside the zip");
}

function askHidden(q){
  return new Promise(res => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = s => { if (s.includes(q)) process.stdout.write(s); };
    rl.question(q, a => { rl.close(); process.stdout.write("\n"); res(a); });
  });
}

const o = args();
if (!o.items.some(it => it.key !== "ask") || o.help){
  console.log(`Usage:
  node build.mjs --in <export.zip|.txt> --pass "<passphrase>" [--out dist/chat.html]
  node build.mjs --chat "Label=<export.zip>" --chat "Other label=<export.zip>" [--ask "Label"] ... --pass "<passphrase>"
Options: --out <file> (default dist/chat.html), --iterations <n> (default 1000000)
Omit --pass to be prompted with hidden input, or set CHAT_PASS.`);
  process.exit(o.help ? 0 : 1);
}
const sources = o.items.map(({ key, val }) => {
  if (typeof val !== "string") { console.error(`--${key} needs a value`); process.exit(1); }
  if (key === "in") return { label: null, file: val };
  if (key === "ask") return { label: val.trim(), ask: true };
  const k = val.indexOf("=");
  if (k < 1) { console.error(`--chat expects "Label=path", got: ${val}`); process.exit(1); }
  return { label: val.slice(0, k).trim(), file: val.slice(k + 1) };
});
for (const s of sources) if (s.file && !fs.existsSync(s.file)) { console.error(`File not found: ${s.file}`); process.exit(1); }
let pass = typeof o.pass === "string" ? o.pass : process.env.CHAT_PASS;
if (!pass){
  pass = await askHidden("Passphrase: ");
  if (pass !== await askHidden("Repeat passphrase: ")){ console.error("Passphrases don't match"); process.exit(1); }
}
if (pass.length < 12) console.warn("⚠  Short passphrase. For a public file use 5+ random words.");

const iterations = Number(o.iterations) || 1_000_000;
const out = o.out || path.join(here, "dist", "chat.html");
const chats = sources.map(s => s.ask ? { label: s.label, ask: true } : { label: s.label, ...readChat(s.file) });

const plain = zlib.gzipSync(Buffer.from(JSON.stringify({ v: 2, chats }), "utf8"), { level: 9 });
const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base,
  { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));

const b64 = b => Buffer.from(b).toString("base64");
const meta = JSON.stringify({ v: 1, kdf: "PBKDF2-SHA256", iterations, salt: b64(salt), iv: b64(iv) });

let html = fs.readFileSync(path.join(here, "index.html"), "utf8");
const unlock = fs.readFileSync(path.join(here, "unlock.js"), "utf8");
html = html
  .replace("<title>WhatsApp Chat Viewer</title>", '<title>Locked chat</title>\n<meta name="robots" content="noindex,nofollow">')
  .replace("</body>", `<script type="application/json" id="encMeta">${meta}</script>\n` +
    `<script type="text/plain" id="encData">${b64(ct)}</script>\n<script>\n${unlock}</script>\n</body>`);

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, html);
console.log(`✓ ${out}  (${chats.length} chat${chats.length > 1 ? "s" : ""}, ${(fs.statSync(out).size / 1048576).toFixed(1)} MB, ${iterations.toLocaleString("en-US")} PBKDF2 iterations)`);
