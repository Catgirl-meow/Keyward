import { rpc } from "../../platform/messages.ts";
import { toast } from "../components/kit.tsx";

/** Copies from a page (user gesture) and asks the background to clear it later. */
export async function copyText(text: string, what = "Copied", sensitive = true): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast(what === "Copied" ? "Copied" : `${what} copied`);
    if (sensitive) void rpc("clipboard.copy", { text, sensitive: true }).catch(() => {});
  } catch {
    toast("Could not copy", { tone: "error" });
  }
}
