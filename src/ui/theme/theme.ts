import type { Settings } from "../../platform/settings.ts";

type Palettes = typeof import("./palettes.gen.ts").PALETTES;
const mq = typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)") : null;
const CACHE = "kw-theme-v1";

export function isDark(s: Pick<Settings, "theme">): boolean {
  return s.theme === "dark" || (s.theme === "system" && !!mq?.matches);
}

// The 18 generated palettes (~19 KB) load only when the accent changes or the Appearance page
// opens; the roles of the current accent are cached in localStorage, which is synchronous, so the
// first paint already has the right colors.
let palettes: Palettes | null = null;
export async function loadPalettes(): Promise<Palettes> {
  return (palettes ??= (await import("./palettes.gen.ts")).PALETTES);
}

interface Cached {
  accent: string;
  light: Record<string, string>;
  dark: Record<string, string>;
}

function readCache(): Cached | null {
  try {
    return JSON.parse(localStorage.getItem(CACHE) ?? "null");
  } catch {
    return null;
  }
}

function setVars(roles: Record<string, string>) {
  const st = document.documentElement.style;
  for (const k in roles) st.setProperty(`--${k}`, roles[k]);
}

export function applyTheme(s: Pick<Settings, "theme" | "amoled" | "accent" | "font">): void {
  const root = document.documentElement;
  const dark = isDark(s);
  root.dataset.theme = dark ? "dark" : "light";
  root.dataset.amoled = String(dark && s.amoled);
  root.dataset.font = s.font;
  const cached = readCache();
  if (cached?.accent === s.accent) return setVars(dark ? cached.dark : cached.light);
  if (cached) setVars(dark ? cached.dark : cached.light); // previous accent until the new one loads
  void loadPalettes().then((all) => {
    const pal = all[s.accent] ?? all.default;
    try {
      localStorage.setItem(CACHE, JSON.stringify({ accent: s.accent, light: pal.light, dark: pal.dark } satisfies Cached));
    } catch {}
    setVars(isDark(s) ? pal.dark : pal.light);
  });
}

/** Applies the cached theme before anything async runs (call first thing in a page). */
export function applyCachedTheme(): void {
  const c = readCache();
  if (!c) return;
  const root = document.documentElement;
  const dark = !!mq?.matches;
  root.dataset.theme = dark ? "dark" : "light";
  setVars(dark ? c.dark : c.light);
}

export function watchSystemTheme(get: () => Settings): () => void {
  if (!mq) return () => {};
  const on = () => applyTheme(get());
  mq.addEventListener("change", on);
  return () => mq.removeEventListener("change", on);
}

export async function accents(): Promise<{ id: string; label: string; seed: string }[]> {
  return Object.entries(await loadPalettes()).map(([id, p]) => ({ id, label: p.label, seed: p.seed }));
}

/** Keyguard's item accent: 60 hues in 6° steps from a hash of the id. */
export function accentHue(seed: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return ((h >>> 0) % 60) * 6;
}

export function hsvToRgb(h: number, s: number, v: number): string {
  const f = (n: number) => {
    const k = (n + h / 60) % 6;
    return Math.round((v - v * s * Math.max(0, Math.min(k, 4 - k, 1))) * 255);
  };
  return `rgb(${f(5)} ${f(3)} ${f(1)})`;
}

export function itemAccent(seed: string, sat = 0.8): string {
  return hsvToRgb(accentHue(seed), sat, 0.8);
}
