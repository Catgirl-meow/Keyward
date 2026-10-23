import type { ComponentChildren } from "preact";
import { Banner } from "../components/kit.tsx";
import { settings } from "../data/app.ts";

/** "Set by <organization>" under a control an organization policy restricts. */
export function PolicyNote({ type, children }: { type: number; children?: ComponentChildren }) {
  const by = settings.value.policy?.by[type];
  if (!by) return null;
  return <Banner tone="info">{children ?? "Restricted"} by {by}'s policy.</Banner>;
}
