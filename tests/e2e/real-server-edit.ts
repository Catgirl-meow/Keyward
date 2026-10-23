// Saves an edit to an item on the real server through the API, with the same request body the
// extension sends (encryptCipher). Run after a Vaultwarden upgrade: 1.37.4 started rejecting
// item writes without "encryptedFor" (422), which tests on an older local server can't catch.
//   node tests/e2e/real-server-edit.ts
import assert from "node:assert/strict";
import { testEnv } from "./launch.ts";
import { decryptCipher, encryptCipher } from "../../src/core/vault/cipher.ts";

const env = testEnv();
if (!env.KW_REAL_SERVER) throw new Error("no KW_REAL_SERVER in tests/.env.test");
process.env.KW_SERVER = env.KW_REAL_SERVER;
const vw = await import("../lib/vw.ts");
if (!env.KW_REAL_EMAIL || !env.KW_REAL_PASSWORD) throw new Error("no KW_REAL_EMAIL / KW_REAL_PASSWORD in tests/.env.test");

const s = await vw.login(env.KW_REAL_EMAIL, env.KW_REAL_PASSWORD);
const raw = (await vw.sync(s)).ciphers[0];
if (!raw) throw new Error("the test account has no items (run tests/e2e/real-server.ts first)");
const v = await decryptCipher(raw, s.ring);
const notes = `edited ${new Date().toISOString()}`;
const { body } = await encryptCipher({ ...v, notes }, s.ring, { base: raw, useItemKey: true, encryptedFor: s.login.userId });
await s.api.put(`/ciphers/${raw.id}`, body);
const back = await decryptCipher(await s.api.get(`/ciphers/${raw.id}`), s.ring);
assert.equal(back.notes, notes);
console.log(`real server accepted the edit of "${v.name}"`);
