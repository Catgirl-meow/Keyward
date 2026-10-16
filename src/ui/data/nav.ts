import { signal } from "@preact/signals";
import type { ItemKind } from "../../core/vault/types.ts";

export type Tab = "vault" | "generator" | "send" | "watchtower" | "gpg" | "settings";

export type Route =
  | { name: "home" }
  | { name: "item"; id: string }
  | { name: "edit"; id?: string; type?: ItemKind; prefill?: Record<string, any> }
  | { name: "gpg-tools"; key?: string }
  | { name: "settings-page"; page: string }
  | { name: "send-edit"; id?: string; type?: number }
  | { name: "watch-list"; check: string }
  | { name: "history"; id: string }
  | { name: "folders" }
  | { name: "trash" };

export const tab = signal<Tab>("vault");
export const stack = signal<Route[]>([{ name: "home" }]);
export const direction = signal<"forward" | "back">("forward");

export function push(r: Route) {
  direction.value = "forward";
  stack.value = [...stack.value, r];
}
export function pop() {
  if (stack.value.length <= 1) return;
  direction.value = "back";
  stack.value = stack.value.slice(0, -1);
}
export function replace(r: Route) {
  direction.value = "forward";
  stack.value = [...stack.value.slice(0, -1), r];
}
export function home(t?: Tab) {
  direction.value = "back";
  if (t) tab.value = t;
  stack.value = [{ name: "home" }];
}
export function top(): Route {
  return stack.value[stack.value.length - 1];
}
