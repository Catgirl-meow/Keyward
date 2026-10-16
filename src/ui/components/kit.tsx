import { signal } from "@preact/signals";
import type { ButtonHTMLAttributes, ComponentChildren, JSX } from "preact";
import { createPortal } from "preact/compat";
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import * as I from "../icons/index.ts";
import { itemAccent } from "../theme/theme.ts";

export function Icon({ d, size = 24, class: cls = "", title }: { d: string; size?: number; class?: string; title?: string }) {
  return (
    <svg class={`icon ${cls}`} viewBox="0 -960 960 960" width={size} height={size} aria-hidden={title ? undefined : "true"} role={title ? "img" : undefined}>
      {title && <title>{title}</title>}
      <path d={d} />
    </svg>
  );
}

type BtnProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "icon" | "label"> & { icon: string; label: string; on?: boolean; small?: boolean; size?: number };
export function IconButton({ icon, label, on, small, size, class: cls = "", ...rest }: BtnProps) {
  return (
    <button type="button" class={`icon-btn ${small ? "sm" : ""} ${cls}`} aria-label={label} title={label} data-on={on ? "true" : undefined} {...rest}>
      <Icon d={icon} size={size ?? (small ? 20 : 24)} />
    </button>
  );
}

export function Spinner({ size = 24 }: { size?: number }) {
  return (
    <svg class="spinner" viewBox="0 0 50 50" width={size} height={size} aria-label="Loading">
      <circle cx="25" cy="25" r="20" />
    </svg>
  );
}

type ButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "icon" | "type"> & {
  variant?: "filled" | "tonal" | "outlined" | "text" | "danger";
  icon?: string;
  loading?: boolean;
  full?: boolean;
  disabled?: boolean;
  type?: "button" | "submit";
};
export function Button({ variant = "filled", icon, loading, full, children, class: cls = "", disabled, type = "button", ...rest }: ButtonProps) {
  const v = variant === "danger" ? "danger" : variant;
  return (
    <button type={type} class={`btn ${v} ${icon || loading ? "has-icon" : ""} ${full ? "full" : ""} ${cls}`} disabled={disabled || loading} {...rest}>
      {loading ? <Spinner size={18} /> : icon ? <Icon d={icon} size={18} /> : null}
      {children}
    </button>
  );
}

export interface FieldProps {
  label?: string;
  value: string;
  onInput?: (v: string) => void;
  type?: string;
  mono?: boolean;
  multiline?: boolean;
  /** textarea height in lines (multiline only) */
  rows?: number;
  autoFocus?: boolean;
  placeholder?: string;
  hint?: ComponentChildren;
  error?: string | null;
  trailing?: ComponentChildren;
  leading?: ComponentChildren;
  name?: string;
  autocomplete?: string;
  readOnly?: boolean;
  inputMode?: "none" | "text" | "tel" | "url" | "email" | "numeric" | "decimal" | "search";
  maxLength?: number;
  onKeyDown?: (e: KeyboardEvent) => void;
  onBlur?: () => void;
  id?: string;
  spellcheck?: boolean;
}
export function TextField(p: FieldProps) {
  const ref = useRef<HTMLInputElement & HTMLTextAreaElement>(null);
  useEffect(() => {
    if (p.autoFocus) requestAnimationFrame(() => ref.current?.focus());
  }, []);
  const filled = p.value !== "" || !!p.placeholder;
  const common = {
    ref,
    id: p.id,
    name: p.name,
    value: p.value,
    placeholder: p.placeholder,
    readOnly: p.readOnly,
    "aria-label": p.label,
    "aria-invalid": p.error ? true : undefined,
    autoComplete: p.autocomplete ?? "off",
    spellcheck: p.spellcheck ?? false,
    class: p.mono ? "mono" : "",
    onInput: (e: any) => p.onInput?.(e.currentTarget.value),
    onKeyDown: p.onKeyDown as any,
    onBlur: p.onBlur,
  };
  return (
    <div>
      <div class={`field ${filled ? "filled" : ""} ${p.error ? "error" : ""} ${p.label ? "" : "no-label"}`}>
        {p.leading && <div class="lead">{p.leading}</div>}
        {p.label && <label>{p.label}</label>}
        {p.multiline ? <textarea {...(common as any)} rows={p.rows ?? 3} /> : <input {...(common as any)} type={p.type ?? "text"} inputMode={p.inputMode} maxLength={p.maxLength} />}
        {p.trailing && <div class="trail">{p.trailing}</div>}
      </div>
      {(p.error || p.hint) && <div class={`field-hint ${p.error ? "error" : ""}`}>{p.error || p.hint}</div>}
    </div>
  );
}

export function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return (
    <div class="field filled select">
      <label>{label}</label>
      <select value={value} onChange={(e) => onChange(e.currentTarget.value)} aria-label={label}>
        {options.map(([v, l]) => (
          <option value={v} key={v}>{l}</option>
        ))}
      </select>
      <div class="trail" aria-hidden="true"><Icon d={I.down} /></div>
    </div>
  );
}

/** Password field with reveal toggle (and optional extra trailing actions). */
export function SecretField(p: FieldProps & { extra?: ComponentChildren }) {
  const [show, setShow] = useState(false);
  return (
    <TextField
      {...p}
      type={show ? "text" : "password"}
      mono={show || p.mono}
      trailing={
        <>
          {p.extra}
          <IconButton icon={show ? I.eyeOff : I.eye} label={show ? "Hide" : "Show"} onClick={() => setShow(!show)} />
        </>
      }
    />
  );
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return <button type="button" role="switch" class="switch" aria-checked={checked} aria-label={label} onClick={(e) => { e.stopPropagation(); onChange(!checked); }} />;
}

/**
 * Rows of chips scroll sideways; a mouse wheel only scrolls up and down. Over a chip row that
 * can still move that way, the wheel scrolls it sideways instead (at either end the page
 * scrolls as usual). Touchpads send sideways scrolling themselves and are left alone.
 */
export function chipsFollowWheel() {
  addEventListener("wheel", (e) => {
    const row = (e.target as Element | null)?.closest?.<HTMLElement>(".chips");
    if (!row || e.ctrlKey || Math.abs(e.deltaX) >= Math.abs(e.deltaY)) return;
    const max = row.scrollWidth - row.clientWidth;
    if (max <= 0) return;
    const dy = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? row.clientWidth : 1);
    if ((dy < 0 && row.scrollLeft <= 0) || (dy > 0 && row.scrollLeft >= max - 1)) return;
    e.preventDefault();
    row.scrollLeft += dy;
  }, { passive: false });
}

export function Chip({ selected, onClick, icon, children, closable }: { selected?: boolean; onClick?: () => void; icon?: string; children: ComponentChildren; closable?: boolean }) {
  return (
    <button type="button" class="chip" aria-pressed={!!selected} onClick={onClick}>
      {selected ? <Icon d={closable ? I.close : I.check} size={18} /> : icon ? <Icon d={icon} size={18} /> : null}
      {children}
    </button>
  );
}

export function Badge({ tone, icon, children, title }: { tone?: "ok" | "warn" | "error" | "info" | "outline"; icon?: string; children?: ComponentChildren; title?: string }) {
  return (
    <span class={`badge ${tone ?? ""}`} title={title}>
      {icon && <Icon d={icon} size={16} />}
      {children}
    </span>
  );
}

export function Group({ label, children }: { label?: string; children: ComponentChildren }) {
  return (
    <>
      {label && <div class="section-label">{label}</div>}
      <div class="group">{children}</div>
    </>
  );
}

export interface RowProps {
  leading?: ComponentChildren;
  title: ComponentChildren;
  sub?: ComponentChildren;
  trailing?: ComponentChildren;
  below?: ComponentChildren;
  onClick?: (e: MouseEvent) => void;
  onContextMenu?: (e: MouseEvent) => void;
  selected?: boolean;
  /** Title and subtitle on one line each, cut with "…": for list rows (the vault list's
   * windowing estimates their height). Elsewhere they wrap, so nothing is cut off. */
  oneLine?: boolean;
  class?: string;
  href?: string;
  id?: string;
  title_?: string;
}
export function Row(p: RowProps) {
  const cls = `item ${p.onClick ? "click" : ""} ${p.selected ? "selected" : ""} ${p.oneLine ? "one-line" : ""} ${p.class ?? ""}`;
  const inner = (
    <>
      {p.leading}
      <div class="text">
        <div class="title">{p.title}</div>
        {p.sub != null && p.sub !== "" && <div class="sub">{p.sub}</div>}
        {p.below && <div class="below">{p.below}</div>}
      </div>
      {p.trailing && <div class="trail">{p.trailing}</div>}
    </>
  );
  if (p.onClick)
    return (
      <div role="button" tabIndex={0} id={p.id} class={cls} title={p.title_} onClick={p.onClick} onContextMenu={p.onContextMenu}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); p.onClick!(e as any); } }}>
        {inner}
      </div>
    );
  return <div class={cls} id={p.id}>{inner}</div>;
}

export function Avatar({ seed, name, icon, src, badges, sat }: { seed: string; name?: string; icon?: string; src?: string | null; badges?: string[]; sat?: number }) {
  const [failed, setFailed] = useState(false);
  const letters = initials(name ?? "");
  const color = itemAccent(seed, sat);
  const bg = `color-mix(in srgb, ${color} 75%, var(--page-bg))`;
  const showImg = src && !failed;
  return (
    <div class={`avatar ${showImg ? "fav" : ""}`} style={{ background: showImg ? undefined : bg }}>
      <div class="ring">
        {showImg ? (
          <img
            src={src}
            alt=""
            loading="lazy"
            decoding="async"
            referrerpolicy="no-referrer"
            onError={() => setFailed(true)}
            // Vaultwarden answers unknown sites with a 19×19 grey globe: show initials instead.
            onLoad={(e) => e.currentTarget.naturalWidth === 19 && e.currentTarget.naturalHeight === 19 && setFailed(true)}
          />
        ) : icon ? <Icon d={icon} size={20} /> : letters}
      </div>
      {badges && badges.length > 0 && (
        <div class="badges">
          {badges.map((b) => (
            <Icon d={b} size={12} />
          ))}
        </div>
      )}
    </div>
  );
}

export function initials(name: string): string {
  const words = name.trim().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  if (!words.length) return "?";
  const a = [...words[0]][0] ?? "";
  const b = words.length > 1 ? [...words[1]][0] ?? "" : [...words[0]][1] ?? "";
  return (a + b).toUpperCase();
}

export function EmptyState({ text, children, icon }: { text: string; children?: ComponentChildren; icon?: string }) {
  return (
    <div class="empty fade-in">
      {icon ? <Icon d={icon} size={64} /> : <PixelFace />}
      <div class="msg">{text}</div>
      {children}
    </div>
  );
}

/** Keyguard's blinking pixel-art face. */
export function PixelFace() {
  return (
    <svg class="face" viewBox="0 0 16 16" shape-rendering="crispEdges" aria-hidden="true">
      <rect x="1" y="1" width="14" height="14" rx="3" fill="var(--sc-highest)" />
      <g fill="var(--on-surface-variant)">
        <rect class="eye" x="4" y="5" width="2" height="3" />
        <rect class="eye" x="10" y="5" width="2" height="3" />
        <rect x="5" y="11" width="6" height="1" />
      </g>
      <style>{`.eye{transform-origin:center 6.5px;animation:blink 4s infinite}@keyframes blink{0%,92%,100%{transform:scaleY(1)}95%{transform:scaleY(.1)}}`}</style>
    </svg>
  );
}

export function Skeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div class="group shimmer">
      {Array.from({ length: rows }, (_, i) => (
        <div class="item skeleton" key={i}>
          <div class="ava" />
          <div class="col grow" style={{ gap: "6px" }}>
            <div class="bar" style={{ width: "45%", height: "16px" }} />
            <div class="bar" style={{ width: "33%", height: "14px" }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function TotpRing({ remaining, period }: { remaining: number; period: number }) {
  const c = 2 * Math.PI * 6;
  return (
    <svg class="totp-ring" viewBox="0 0 16 16" aria-hidden="true">
      <circle class="track" cx="8" cy="8" r="6" />
      <circle class="bar" cx="8" cy="8" r="6" stroke-dasharray={c} stroke-dashoffset={c * (1 - remaining / period)} />
    </svg>
  );
}

/** Colors digits and symbols like Keyguard's password text. */
export function ColoredPassword({ value }: { value: string }) {
  const parts: JSX.Element[] = [];
  let i = 0;
  for (const ch of value) {
    const cls = /\d/.test(ch) ? "d" : /[^\p{L}\p{N}\s]/u.test(ch) ? "s" : "";
    parts.push(cls ? <span class={cls} key={i}>{ch}</span> : <>{ch}</>);
    i++;
  }
  return <span class="pw mono">{parts}</span>;
}

// ---------------- toasts ----------------
interface Toast {
  id: number;
  msg: string;
  tone?: "ok" | "error";
  action?: { label: string; run: () => void };
}
const toasts = signal<Toast[]>([]);
let toastId = 0;
export function toast(msg: string, opts: { tone?: "ok" | "error"; action?: Toast["action"]; ms?: number } = {}) {
  const t: Toast = { id: ++toastId, msg, tone: opts.tone, action: opts.action };
  toasts.value = [...toasts.value.slice(-2), t];
  setTimeout(() => (toasts.value = toasts.value.filter((x) => x.id !== t.id)), opts.ms ?? (opts.tone === "error" ? 5000 : 2500));
}
export function Toasts() {
  return (
    <div class="toasts" role="status" aria-live="polite">
      {toasts.value.map((t) => (
        <div class={`toast ${t.tone ?? ""}`} key={t.id}>
          {t.tone && <Icon d={t.tone === "ok" ? I.checkCircle : I.error} size={20} />}
          <div class="msg">{t.msg}</div>
          {t.action && (
            <button class="btn text" onClick={() => { t.action!.run(); toasts.value = toasts.value.filter((x) => x.id !== t.id); }}>
              {t.action.label}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------- menus ----------------
export interface MenuItem {
  icon?: string;
  label: string;
  run?: () => void;
  danger?: boolean;
  divider?: boolean;
  header?: boolean;
}
const menuState = signal<{ x: number; y: number; items: MenuItem[]; align: "left" | "right" } | null>(null);
/** The button the open menu came from, and the one whose press just closed it. */
let menuAnchor: HTMLElement | null = null;
let closedBy: { el: HTMLElement; at: number } | null = null;

export function openMenu(anchor: HTMLElement | MouseEvent, items: MenuItem[]) {
  // A press on the button of an open menu closes it (pointerdown, in MenuHost); the click that
  // follows must not open it again, so the button toggles its menu.
  if (!(anchor instanceof MouseEvent) && closedBy?.el === anchor && performance.now() - closedBy.at < 800) {
    closedBy = null;
    return;
  }
  closedBy = null;
  menuAnchor = anchor instanceof MouseEvent ? null : anchor;
  let x: number, y: number, align: "left" | "right" = "right";
  if (anchor instanceof MouseEvent) {
    x = anchor.clientX;
    y = anchor.clientY;
    align = x > innerWidth / 2 ? "right" : "left";
  } else {
    const r = anchor.getBoundingClientRect();
    x = r.right;
    y = r.bottom + 4;
    align = r.left + r.width / 2 > innerWidth / 2 ? "right" : "left";
    if (align === "left") x = r.left;
  }
  menuState.value = { x, y, items, align };
}
export function closeMenu() {
  menuState.value = null;
}
export function MenuHost() {
  const ref = useRef<HTMLDivElement>(null);
  const m = menuState.value;
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || !m) return;
    const r = el.getBoundingClientRect();
    let left = m.align === "right" ? m.x - r.width : m.x;
    let top = m.y;
    left = Math.max(8, Math.min(left, innerWidth - r.width - 8));
    if (top + r.height > innerHeight - 8) top = Math.max(8, m.y - r.height - 8);
    el.style.left = left + "px";
    el.style.top = top + "px";
    (el.querySelector("button") as HTMLElement | null)?.focus();
  }, [m]);
  useEffect(() => {
    if (!m) return;
    const close = (e: Event) => {
      if (e instanceof KeyboardEvent && e.key !== "Escape") return;
      if (e.type === "pointerdown" && ref.current?.contains(e.target as Node)) return;
      if (e.type === "pointerdown" && menuAnchor?.contains(e.target as Node)) closedBy = { el: menuAnchor, at: performance.now() };
      closeMenu();
    };
    addEventListener("pointerdown", close, true);
    addEventListener("keydown", close, true);
    addEventListener("blur", closeMenu);
    return () => {
      removeEventListener("pointerdown", close, true);
      removeEventListener("keydown", close, true);
      removeEventListener("blur", closeMenu);
    };
  }, [m]);
  if (!m) return null;
  return createPortal(
    <div class="menu" ref={ref} role="menu" style={{ left: "-999px", top: "-999px" }}>
      {m.items.map((it, i) =>
        it.divider ? (
          <hr key={i} />
        ) : it.header ? (
          <div class="menu-label" key={i}>{it.label}</div>
        ) : (
          <button key={i} role="menuitem" class={it.danger ? "danger" : ""} onClick={() => { closeMenu(); it.run?.(); }}>
            {it.icon && <Icon d={it.icon} size={20} />}
            <span class="grow ellipsis">{it.label}</span>
          </button>
        ),
      )}
    </div>,
    document.body,
  );
}

// ---------------- dialogs / sheets ----------------
export function Sheet({ onClose, children, center }: { onClose: () => void; children: ComponentChildren; center?: boolean }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && (e.stopPropagation(), onClose());
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, [onClose]);
  return createPortal(
    <div class={`scrim ${center ? "center" : ""}`} onPointerDown={(e) => e.target === e.currentTarget && onClose()}>
      {center ? <div class="dialog" role="dialog" aria-modal="true">{children}</div> : (
        <div class="sheet" role="dialog" aria-modal="true">
          <div class="handle" />
          {children}
        </div>
      )}
    </div>,
    document.body,
  );
}

interface ConfirmReq {
  title: string;
  text?: string;
  ok: string;
  danger?: boolean;
  resolve: (v: boolean) => void;
}
const confirmState = signal<ConfirmReq | null>(null);
export function confirm(title: string, text?: string, ok = "OK", danger = false): Promise<boolean> {
  return new Promise((resolve) => (confirmState.value = { title, text, ok, danger, resolve }));
}
export function ConfirmHost() {
  const c = confirmState.value;
  if (!c) return null;
  const done = (v: boolean) => {
    confirmState.value = null;
    c.resolve(v);
  };
  return (
    <Sheet center onClose={() => done(false)}>
      <h2>{c.title}</h2>
      {c.text && <p class="t-body-m med" style={{ margin: 0 }}>{c.text}</p>}
      <div class="actions">
        <Button variant="text" onClick={() => done(false)}>Cancel</Button>
        <Button variant={c.danger ? "danger" : "filled"} onClick={() => done(true)}>{c.ok}</Button>
      </div>
    </Sheet>
  );
}

export function Banner({ tone, icon, children }: { tone: "error" | "warn" | "info"; icon?: string; children: ComponentChildren }) {
  return (
    <div class={`banner ${tone}`} role={tone === "error" ? "alert" : undefined}>
      <Icon d={icon ?? (tone === "error" ? I.error : tone === "warn" ? I.warning : I.info)} size={20} />
      <div class="grow t-body-m">{children}</div>
    </div>
  );
}

export function TopBar({ title, back, actions, small, scrolled }: { title?: ComponentChildren; back?: () => void; actions?: ComponentChildren; small?: boolean; scrolled?: boolean }) {
  return (
    <div class={`topbar ${scrolled ? "scrolled" : ""}`}>
      {back && <IconButton icon={I.back} label="Back" onClick={back} />}
      <div class={`heading ${small ? "sm" : ""}`} style={back ? undefined : { paddingLeft: "12px" }}>{title}</div>
      {actions}
    </div>
  );
}
