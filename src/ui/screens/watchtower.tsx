// Watchtower: the vault's health at a glance (a card per check) and the items behind each card.
import { useEffect } from "preact/hooks";
import type { CheckId } from "../../core/watchtower/report.ts";
import { Banner, EmptyState, Group, Icon, IconButton, Row, Skeleton, Spinner, TopBar } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { items } from "../data/app.ts";
import { pop, push } from "../data/nav.ts";
import { checkExposed, checkInactive2fa, checking, net, report, reportError, runReport, type NetCheck } from "../data/watchtower.ts";
import { ItemAvatar } from "./vault-list.tsx";

type Tone = "error" | "warn" | "info";
interface Check {
  id: CheckId;
  title: string;
  /** What the check means, shown on its list of items. */
  text: string;
  icon: string;
  tone: Tone;
  /** Network checks: what leaves the device, shown before the user runs one. */
  ask?: string;
}

export const CHECKS: Check[] = [
  { id: "exposed", title: "Exposed passwords", icon: I.dataAlert, tone: "error",
    text: "These passwords appear in known data breaches. Change them, and anywhere else you used them.",
    ask: "Check with Have I Been Pwned. Only the first 5 characters of each password's SHA-1 hash are sent." },
  { id: "reused", title: "Reused passwords", icon: I.repeat, tone: "error",
    text: "One leak exposes every account that shares a password. Give each of these its own." },
  { id: "weak", title: "Weak passwords", icon: I.password, tone: "error",
    text: "These passwords are easy to guess. Replace them with generated ones." },
  { id: "insecure", title: "Unsecured websites", icon: I.noEncryption, tone: "warn",
    text: "These logins use plain http, so the password travels unencrypted. Switch the address to https if the site supports it." },
  { id: "inactive2fa", title: "Two-step login available", icon: I.mobileLock, tone: "warn",
    text: "These sites offer one-time codes, but no code is saved here. Turn two-step login on at the site and add the code to the item.",
    ask: "Download the list of sites from 2fa.directory. Nothing about your vault is sent." },
  { id: "weakKeys", title: "Weak SSH keys", icon: I.keyOff, tone: "warn",
    text: "Short RSA and DSA keys can be broken. Generate a new Ed25519 key." },
  { id: "expiring", title: "Expiring cards", icon: I.eventBusy, tone: "warn",
    text: "Cards that have expired or expire within a month." },
  { id: "duplicates", title: "Duplicate items", icon: I.copyAll, tone: "info",
    text: "Logins saved more than once with the same name, username, websites and password." },
  { id: "incomplete", title: "Incomplete items", icon: I.unknownDoc, tone: "info",
    text: "Items missing something they need: a password, a website to fill on, a card number." },
  { id: "empty", title: "Empty items", icon: I.draft, tone: "info",
    text: "Items with nothing saved in them." },
  { id: "trash", title: "Trash", icon: I.del, tone: "info",
    text: "Deleted items. They stay in the trash until you empty it." },
];

const NET: Partial<Record<CheckId, { run: () => Promise<void>; key: NetCheck }>> = {
  exposed: { run: checkExposed, key: "exposed" },
  inactive2fa: { run: checkInactive2fa, key: "inactive2fa" },
};

/** Keeps the report in step with the vault while a Watchtower screen is shown. */
function useReport() {
  const r = report.value;
  const stale = !r || r.basis !== items.value;
  useEffect(() => {
    if (stale && !checking.value) void runReport();
  }, [stale]);
  return r;
}

function ago(t: number): string {
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  return m < 60 ? `${m} min ago` : new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function Card({ c }: { c: Check }) {
  const r = report.value!;
  const found = r.findings[c.id];
  const n = new Set(found?.map((f) => f.id)).size;
  const nc = NET[c.id];
  const ns = nc ? net.value[nc.key] : null;
  // A network check nobody ran yet (or that failed) runs on click; one with results opens them.
  const pending = !!nc && !found;
  const running = ns?.state === "running";
  let body: string;
  if (running) body = ns.total > 1 ? `Checking ${ns.done} of ${ns.total}` : "Checking…";
  else if (ns?.state === "error") body = ns.message;
  else if (pending) body = c.ask!;
  else body = n ? (n === 1 ? "1 item" : `${n} items`) : "Nothing found";
  const tone = n ? c.tone : pending ? "pending" : "clear";
  const onClick = running ? undefined : pending || ns?.state === "error" ? () => void nc!.run() : n ? () => push({ name: "watch-list", check: c.id }) : undefined;
  return (
    <button type="button" class={`wt-card ${tone}`} data-check={c.id} data-count={pending ? "" : String(n)} data-state={ns?.state} disabled={!onClick} onClick={onClick}>
      <div class="wt-card-top">
        <span class="wt-ico"><Icon d={c.icon} /></span>
        <span class="wt-count">{running ? <Spinner size={28} /> : pending ? <Icon d={I.refresh} /> : n}</span>
      </div>
      <div class="wt-title">{c.title}</div>
      <div class={`wt-text ${ns?.state === "error" ? "error-text" : ""}`}>{body}</div>
    </button>
  );
}

export function WatchtowerScreen() {
  const r = useReport();
  const refresh = (
    <IconButton icon={I.refresh} label="Check again" class={checking.value ? "spin-slow" : ""} disabled={checking.value}
      onClick={() => {
        // Run the network checks that already ran again too.
        void runReport().then(() => (Object.keys(NET) as CheckId[]).forEach((c) => net.value[NET[c]!.key].state === "done" && void NET[c]!.run()));
      }} />
  );
  if (!r) {
    return (
      <div class="watchtower">
        <TopBar title="Watchtower" actions={refresh} />
        {reportError.value ? <div class="pad"><Banner tone="error">Couldn't check the vault: {reportError.value}</Banner></div> : <Skeleton rows={4} />}
      </div>
    );
  }
  const issues = new Set(CHECKS.filter((c) => c.tone !== "info").flatMap((c) => r.findings[c.id]?.map((f) => f.id) ?? []));
  return (
    <div class="watchtower">
      <TopBar title="Watchtower" actions={refresh} />
      <div class={`wt-summary ${issues.size ? "warn" : "ok"}`}>
        <Icon d={issues.size ? I.warning : I.health} size={32} />
        <div class="grow">
          <div class="wt-summary-title">{issues.size ? `${issues.size} ${issues.size === 1 ? "item needs" : "items need"} attention` : "No problems found"}</div>
          <div class="wt-summary-sub">{r.total} {r.total === 1 ? "item" : "items"} checked {ago(r.at)} · on this device</div>
        </div>
      </div>
      <div class="wt-grid">
        {CHECKS.map((c) => <Card key={c.id} c={c} />)}
      </div>
    </div>
  );
}

export function WatchList({ check }: { check: string }) {
  const r = useReport();
  const c = CHECKS.find((x) => x.id === check);
  if (!c) return null;
  const rows = (r?.findings[c.id] ?? []).flatMap((f) => {
    const s = items.value.get(f.id);
    return s ? [{ f, s }] : [];
  });
  return (
    <div class="watch-list">
      <TopBar title={c.title} back={pop} />
      <p class="pad t-body-m wt-explain">{c.text}</p>
      {!r ? <Skeleton rows={4} /> : rows.length ? (
        <Group>
          {rows.map(({ f, s }) => (
            <Row key={`${f.id}:${f.detail}`} leading={<ItemAvatar s={s} />} title={s.name || "(no name)"} sub={<span class={`wt-detail ${c.tone}`}>{f.detail}</span>}
              trailing={<Icon d={I.chevron} class="med" />} onClick={() => push({ name: "item", id: s.id })} />
          ))}
        </Group>
      ) : <EmptyState text="Nothing left here" />}
    </div>
  );
}
