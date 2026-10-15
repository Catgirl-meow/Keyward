// Copy from the background (context menu, TOTP after fill) and clear later — but only if the
// clipboard still holds what we put there.
import { sha256 } from "../core/crypto/primitives.ts";
import { toB64 } from "../core/util/bytes.ts";
import { loadSettings } from "../platform/settings.ts";
import { session } from "../platform/storage.ts";

async function ensureOffscreen(): Promise<void> {
  if (!__CHROMIUM__) return;
  const has = await (chrome.offscreen as any).hasDocument?.().catch(() => false);
  if (has) return;
  await chrome.offscreen
    .createDocument({ url: "offscreen.html", reasons: [chrome.offscreen.Reason.CLIPBOARD], justification: "Copy and clear passwords" })
    .catch((e) => {
      if (!String(e).includes("single offscreen")) throw e;
    });
}

async function write(text: string): Promise<void> {
  if (__CHROMIUM__) {
    await ensureOffscreen();
    await chrome.runtime.sendMessage({ kw: "offscreen", op: "write", text });
  } else {
    await navigator.clipboard.writeText(text);
  }
}

async function read(): Promise<string | null> {
  try {
    if (__CHROMIUM__) {
      await ensureOffscreen();
      return (await chrome.runtime.sendMessage({ kw: "offscreen", op: "read" })) ?? null;
    }
    return await navigator.clipboard.readText();
  } catch {
    return null;
  }
}

export async function copy(text: string, sensitive = true): Promise<void> {
  await write(text);
  if (sensitive) await scheduleClear(text);
}

/** Pages copy themselves (user gesture) and only ask us to clear later. */
export async function scheduleClear(text: string): Promise<void> {
  const { clipboardClearSec } = await loadSettings();
  if (!clipboardClearSec) return;
  await session.set("clip", toB64(await sha256(text)));
  await chrome.alarms.create("clip-clear", { when: Date.now() + Math.max(clipboardClearSec, 30) * 1000 });
}

export async function onClearAlarm(): Promise<void> {
  const want = await session.get<string>("clip");
  await session.remove("clip");
  if (!want) return;
  const cur = await read();
  if (cur != null && toB64(await sha256(cur)) === want) await write("");
  if (__CHROMIUM__) await chrome.offscreen.closeDocument().catch(() => {});
}
