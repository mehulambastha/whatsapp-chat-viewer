# WhatsApp Chat Viewer

A single-page, offline viewer for chats exported from WhatsApp ("Export chat → Without media").

- Open the exported `.zip` or `.txt` — it is read locally in your browser; nothing is uploaded.
- WhatsApp-style bubbles, date chips, dark mode.
- Search messages by text, or jump to any date.

Supports Android and iOS export formats, with or without media.

## Passphrase-locked single file

Bake a chat into one encrypted HTML file you can host anywhere:

```sh
node build.mjs --in "WhatsApp Chat.zip" --pass "five random words go here" --out dist/chat.html
```

- AES-256-GCM, key derived with PBKDF2-SHA256 (1,000,000 iterations). Nothing readable, not even the chat name, is left in the output.
- Omit `--pass` to be prompted (hidden input), or set `CHAT_PASS`.
- Needs Node 18+; no dependencies. Output goes to `dist/`, which is git-ignored.
- Security rests entirely on the passphrase: use 5+ random words.

Several chats in one file, plus chats that stay on the reader's device:

```sh
node build.mjs --chat "Chat A=a.zip" --chat "Chat B=b.zip" --ask "Big one" --out dist/chat.html
```

`--ask "Label"` lists a chat without storing anything from it in the page; the reader opens that chat's export
(e.g. a large "with media" zip) from their device, and photos, videos and voice notes are shown inline.
