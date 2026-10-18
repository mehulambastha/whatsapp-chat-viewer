// Injected by build.mjs: swaps the file picker for a passphrase prompt and
// decrypts the embedded chat in the browser (AES-256-GCM, PBKDF2-SHA256 key).
(() => {
  "use strict";
  const meta = JSON.parse(document.getElementById("encMeta").textContent);
  const fromB64 = s => Uint8Array.from(atob(s.trim()), c => c.charCodeAt(0));
  const card = document.getElementById("card");
  card.innerHTML = `
    <h1>🔒 Locked chat</h1>
    <p>Enter the passphrase to open this chat. It's decrypted on this device only.</p>
    <form id="unlockForm" style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
      <input id="pass" type="password" autocomplete="current-password" placeholder="Passphrase" required
        style="flex:1;min-width:200px;padding:10px 14px;border-radius:22px;border:1px solid var(--border);background:var(--input);color:var(--fg);font:inherit;outline:0">
      <button class="btn" type="submit">Unlock</button>
    </form>
    <div id="loadMsg"></div>`;
  const input = document.getElementById("pass"), msg = document.getElementById("loadMsg");
  input.focus();
  document.getElementById("unlockForm").addEventListener("submit", async e => {
    e.preventDefault();
    msg.textContent = "Unlocking…";
    await new Promise(r => setTimeout(r, 20));
    try {
      const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(input.value), "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: fromB64(meta.salt), iterations: meta.iterations, hash: "SHA-256" },
        base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
      let plain;
      try { plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(meta.iv) }, key, fromB64(document.getElementById("encData").textContent)); }
      catch { msg.textContent = "⚠ Wrong passphrase"; input.select(); return; }
      const ds = new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"));
      const data = JSON.parse(await new Response(ds).text());
      input.value = "";
      await openChats(data.chats || [data]);
    } catch (err) { msg.textContent = "⚠ " + err.message; console.error(err); }
  });
})();
