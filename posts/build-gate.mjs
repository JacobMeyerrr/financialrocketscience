#!/usr/bin/env node
// build-gate.mjs — encrypts the <!-- GATE:START --> ... <!-- GATE:END --> region of a post
// so it only decrypts in the browser for emails on allowlist.txt.
//
// Usage:  node build-gate.mjs [source.html] [output.html] [allowlist.txt]
// Defaults: 2026-9-15-gnc-playbook.source.html -> 2026-9-15-gnc-playbook.html, allowlist.txt
//
// Keep the .source.html file and allowlist.txt PRIVATE (don't upload them to your site or a public repo).
// Only the generated output file gets published.

import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

// ---------- CONFIG ----------
const BUY_URL = "#";            // <-- set to your Stripe Payment Link / Gumroad / Lemon Squeezy URL
const PRICE_LABEL = "";         // e.g. "$19 one-time" (leave "" to hide)
const ITERATIONS = 600000;      // PBKDF2 cost: makes guessing emails slow
// ----------------------------

const [src = "2026-9-15-gnc-playbook.source.html", out = "2026-9-15-gnc-playbook.html", listPath = "allowlist.txt"] = process.argv.slice(2);

const html = readFileSync(src, "utf8");
const m = html.match(/<!-- GATE:START -->([\s\S]*?)<!-- GATE:END -->/);
if (!m) { console.error("No <!-- GATE:START --> ... <!-- GATE:END --> markers found in " + src); process.exit(1); }
const secret = m[1];

const emails = [...new Set(readFileSync(listPath, "utf8").split(/\r?\n/)
  .map(l => l.trim().toLowerCase()).filter(l => l && !l.startsWith("#")))];
if (!emails.length) { console.error("allowlist is empty"); process.exit(1); }

const enc = new TextEncoder();
const b64 = u8 => Buffer.from(u8).toString("base64");
const rand = n => crypto.getRandomValues(new Uint8Array(n));

// 1) Random content key encrypts the questions.
const contentKeyRaw = rand(32);
const contentKey = await crypto.subtle.importKey("raw", contentKeyRaw, "AES-GCM", false, ["encrypt"]);
const iv = rand(12);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, contentKey, enc.encode(secret)));

// 2) For each allowed email, wrap the content key with a key derived from that email.
const salt = rand(16);
const slots = [];
for (const email of emails) {
  const base = await crypto.subtle.importKey("raw", enc.encode(email), "PBKDF2", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const siv = rand(12);
  const sct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: siv }, kek, contentKeyRaw));
  slots.push({ iv: b64(siv), ct: b64(sct) });
}
// Shuffle so slot order doesn't reveal allowlist order.
for (let i = slots.length - 1; i > 0; i--) { const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1); [slots[i], slots[j]] = [slots[j], slots[i]]; }

const data = { v: b64(rand(6)), salt: b64(salt), iter: ITERATIONS, iv: b64(iv), ct: b64(ct), slots };

// 3) Greyed-out teaser: real category headings, fake blurred bars (no real question text).
const cats = [...secret.matchAll(/<p><b>([\s\S]*?)<\/b><\/p>\s*<ul>([\s\S]*?)<\/ul>/g)]
  .map(([, title, list]) => ({ title, n: (list.match(/<li>/g) || []).length }));
const widths = [92, 78, 85, 64, 88, 71, 96, 59, 81, 74];
let w = 0;
const teaser = cats.map(c => `
        <p class="gate-cat"><b>${c.title}</b> <span class="gate-count">· ${c.n} questions</span></p>
        <div class="gate-lines">${Array.from({ length: Math.min(c.n, 4) }, () => `<span class="gate-line" style="width:${widths[w++ % widths.length]}%"></span>`).join("")}</div>`).join("");
const total = cats.reduce((s, c) => s + c.n, 0);

const gate = `
      <style>
        .gate{position:relative;margin:1.25rem 0 2rem;}
        .gate-teaser{filter:blur(3px);opacity:.55;user-select:none;pointer-events:none;}
        .gate-cat{margin:1.1rem 0 .5rem;}
        .gate-count{color:#888;font-weight:normal;font-size:.85rem;}
        .gate-lines{padding-left:1.4rem;}
        .gate-line{display:block;height:.8rem;margin:.55rem 0;border-radius:3px;background:rgba(127,127,127,.35);}
        .gate-panel{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:min(440px,92%);padding:1.4rem 1.5rem;border:1px solid #2e2e2e;border-radius:6px;background:var(--bg,#111);box-shadow:0 10px 40px rgba(0,0,0,.35);text-align:center;}
        .gate-panel h3{margin:0 0 .4rem;}
        .gate-panel p{margin:.4rem 0;font-size:.9rem;}
        .gate-form{display:flex;gap:.5rem;margin:.9rem 0 .4rem;}
        .gate-form input{flex:1;min-width:0;font:inherit;padding:.5rem .7rem;border:1px solid #2e2e2e;border-radius:4px;background:rgba(127,127,127,.08);color:inherit;}
        .gate-form button{font:inherit;padding:.5rem .9rem;border:1px solid #2e2e2e;border-radius:4px;background:rgba(127,127,127,.18);color:inherit;cursor:pointer;}
        .gate-form button:disabled{opacity:.6;cursor:wait;}
        .gate-msg{min-height:1.2em;color:#d77;}
        .gate-buy a{font-weight:bold;}
      </style>
      <div class="gate" id="gnc-gate">
        <div class="gate-teaser" aria-hidden="true">${teaser}
        </div>
        <div class="gate-panel" role="region" aria-label="Unlock the question bank">
          <h3>The full question bank is members-only</h3>
          <p>${total} representative questions across ${cats.length} categories. Enter the email you purchased with to unlock it.</p>
          <form class="gate-form" id="gate-form">
            <input type="email" id="gate-email" required placeholder="you@example.com" autocomplete="email" aria-label="Email">
            <button type="submit" id="gate-btn">Unlock</button>
          </form>
          <p class="gate-msg" id="gate-msg" aria-live="polite"></p>
          <p class="gate-buy">Don't have access yet? <a href="${BUY_URL}">Get access${PRICE_LABEL ? " – " + PRICE_LABEL : ""}</a></p>
        </div>
      </div>
      <script type="application/json" id="gate-data">${JSON.stringify(data)}</script>
      <script>
      (function(){
        var D = JSON.parse(document.getElementById('gate-data').textContent);
        var KEY = 'gncGate:' + D.v;
        function b64(s){ return Uint8Array.from(atob(s), function(c){ return c.charCodeAt(0); }); }
        function toB64(u){ var s=''; for (var i=0;i<u.length;i++) s+=String.fromCharCode(u[i]); return btoa(s); }
        var S = window.crypto && window.crypto.subtle;
        var msg = document.getElementById('gate-msg');
        if (!S) { msg.textContent = 'Your browser can\\'t unlock this page (needs HTTPS).'; return; }

        async function kekFor(email){
          var base = await S.importKey('raw', new TextEncoder().encode(email.trim().toLowerCase()), 'PBKDF2', false, ['deriveKey']);
          return S.deriveKey({name:'PBKDF2', salt:b64(D.salt), iterations:D.iter, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['decrypt']);
        }
        async function unwrap(kek){
          for (var i=0;i<D.slots.length;i++){
            try { return new Uint8Array(await S.decrypt({name:'AES-GCM', iv:b64(D.slots[i].iv)}, kek, b64(D.slots[i].ct))); } catch(e){}
          }
          return null;
        }
        async function reveal(raw){
          var k = await S.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
          var pt = await S.decrypt({name:'AES-GCM', iv:b64(D.iv)}, k, b64(D.ct));
          var box = document.createElement('div');
          box.innerHTML = new TextDecoder().decode(pt);
          document.getElementById('gnc-gate').replaceWith(box);
        }

        // Remember unlock on this browser.
        try {
          var saved = localStorage.getItem(KEY);
          if (saved) reveal(b64(saved)).catch(function(){ try{ localStorage.removeItem(KEY); }catch(e){} });
        } catch(e){}

        document.getElementById('gate-form').addEventListener('submit', async function(ev){
          ev.preventDefault();
          var btn = document.getElementById('gate-btn');
          btn.disabled = true; msg.style.color=''; msg.textContent = 'Checking…';
          try {
            var raw = await unwrap(await kekFor(document.getElementById('gate-email').value));
            if (!raw) { msg.textContent = 'That email isn\\'t on the list. Use the email you purchased with, or get access below.'; return; }
            try { localStorage.setItem(KEY, toB64(raw)); } catch(e){}
            await reveal(raw);
          } catch(e) {
            msg.textContent = 'Something went wrong unlocking. Please try again.';
          } finally { btn.disabled = false; }
        });
      })();
      </script>
`;

writeFileSync(out, html.replace(m[0], () => gate));
console.log(`Wrote ${out}: ${total} questions in ${cats.length} categories encrypted for ${emails.length} email(s).`);
if (BUY_URL === "#") console.warn("WARNING: BUY_URL is still '#'. Set it at the top of build-gate.mjs.");
