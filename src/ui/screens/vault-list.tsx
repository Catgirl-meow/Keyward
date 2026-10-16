import { computed, signal } from "@preact/signals";
import type { JSX } from "preact";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "preact/hooks";
import { faviconHostCheap } from "../data/hosts.ts";
import { search, type Filter, type Hit, type SortKey } from "../../core/vault/search.ts";
import { CipherType, GPG_KIND, kindOf, type ItemKind, type Summary } from "../../core/vault/types.ts";
import { rpc, type PageMatch } from "../../platform/messages.ts";
import { Avatar, Chip, EmptyState, Icon, IconButton, Row, Skeleton, openMenu, toast, Badge, type MenuItem } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { aux, folderNames, iconUrl, items, orgNames, syncNow, syncing, syncStatus, vaultLoaded } from "../data/app.ts";
import { push } from "../data/nav.ts";
import { AccountButton } from "./account-menu.tsx";

export const query = signal("");
export const filter = signal<Filter>({});
export const sort = signal<SortKey>("name");
export const selectedId = signal<string | null>(null);

export const TYPE_META: Record<number, { label: string; plural: string; icon: string }> = {
  [CipherType.Login]: { label: "Login", plural: "Logins", icon: I.key },
  [CipherType.Card]: { label: "Card", plural: "Cards", icon: I.card },
  [CipherType.Identity]: { label: "Identity", plural: "Identities", icon: I.person },
  [CipherType.SecureNote]: { label: "Note", plural: "Notes", icon: I.note },
  [CipherType.SshKey]: { label: "SSH key", plural: "SSH keys", icon: I.terminal },
  [GPG_KIND]: { label: "GPG key", plural: "GPG keys", icon: I.keyVertical },
};

const results = computed<Hit[]>(() => search(items.value.values(), query.value, filter.value, sort.value, folderNames.value));

function highlight(text: string, hits?: [number, number][]): JSX.Element | string {
  if (!hits?.length) return text;
  const out: (JSX.Element | string)[] = [];
  let i = 0;
  for (const [a, b] of hits) {
    if (a < i) continue;
    out.push(text.slice(i, a), <mark>{text.slice(a, b)}</mark>);
    i = b;
  }
  out.push(text.slice(i));
  return <>{out}</>;
}

export function ItemAvatar({ s }: { s: Pick<Summary, "id" | "name" | "type" | "uris" | "fav" | "rp" | "att" | "pk" | "gpg"> }) {
  const host = s.type === CipherType.Login ? faviconHostCheap(s.uris) : null;
  const badges: string[] = [];
  if (s.fav) badges.push(I.starFill);
  if (s.rp) badges.push(I.lockFill);
  if (s.att) badges.push(I.attach);
  return (
    <Avatar
      seed={s.id}
      name={s.name}
      src={host ? iconUrl(host) : null}
      icon={s.type !== CipherType.Login ? TYPE_META[kindOf(s)]?.icon : undefined}
      badges={badges}
    />
  );
}

export function ItemRow({ hit, onOpen, selected, trailing, pos }: { hit: Hit; onOpen: (s: Summary) => void; selected?: boolean; trailing?: JSX.Element; pos?: string }) {
  const s = hit.s;
  const org = s.org ? orgNames.value.get(s.org) : null;
  return (
    <Row
      leading={<ItemAvatar s={s} />}
      title={highlight(s.name || "(no name)", hit.nameHits)}
      sub={s.err ? <span style={{ color: "var(--error)" }}>Some fields could not be decrypted</span> : highlight(s.sub, hit.subHits)}
      below={
        hit.context || s.pk.length ? (
          <>
            {hit.context && <Badge tone="outline" icon={I.manageSearch}>{hit.context}</Badge>}
            {s.pk.length > 0 && !hit.context && <Badge tone="outline" icon={I.passkey}>Passkey</Badge>}
          </>
        ) : undefined
      }
      trailing={
        <>
          {org && <span class="badge" style={{ background: "var(--tertiary-container)", color: "var(--on-tertiary-container)", maxWidth: "80px" }}><span class="ellipsis">{org}</span></span>}
          {trailing ?? <Icon d={I.chevron} size={20} />}
        </>
      }
      selected={selected}
      onClick={() => onOpen(s)}
      id={`row-${s.id}`}
      class={pos ? `vrow ${pos}` : undefined}
    />
  );
}

// ---------------------------------------------------------------- windowed list
// Rows are flattened (section labels + items) and cut into blocks of BLOCK entries. A block renders
// only near the viewport; an off-screen block keeps its measured (or estimated) height, so a
// 2,000-item vault costs about as much as one screenful. Group corners come from classes, not
// :first-child, so flattening doesn't change the look.
type Entry = { kind: "label"; key: string; text: string } | { kind: "item"; key: string; hit: Hit; pos: string };
const BLOCK = 20;
const EST = { label: 44, item: 67, below: 32 };

function buildEntries(list: Hit[], grouped: boolean, favSection: boolean): Entry[] {
  const out: Entry[] = [];
  const push = (label: string, hits: Hit[]) => {
    if (!hits.length) return;
    if (label) out.push({ kind: "label", key: `l:${label}`, text: label });
    hits.forEach((h, i) =>
      out.push({ kind: "item", key: `${label}:${h.s.id}`, hit: h, pos: hits.length === 1 ? "only" : i === 0 ? "first" : i === hits.length - 1 ? "last" : "mid" }),
    );
  };
  if (!grouped) {
    push("", list);
    return out;
  }
  if (favSection) push("Favorites", list.filter((h) => h.s.fav));
  let key = "";
  let run: Hit[] = [];
  for (const h of list) {
    const ch = (h.s.name.trim()[0] ?? "#").toLocaleUpperCase();
    const k = /\p{L}/u.test(ch) ? ch : "#";
    if (k !== key) {
      push(key, run);
      key = k;
      run = [];
    }
    run.push(h);
  }
  push(key, run);
  return out;
}

const estimate = (block: Entry[]) =>
  block.reduce((n, e) => n + (e.kind === "label" ? EST.label : EST.item + (e.hit.context || e.hit.s.pk.length ? EST.below : 0)), 0);

function Block({ entries, index, visible, heights, render }: { entries: Entry[]; index: number; visible: boolean; heights: Map<string, number>; render: (e: Entry) => JSX.Element }) {
  const ref = useRef<HTMLDivElement>(null);
  const key = entries[0]?.key ?? String(index);
  useLayoutEffect(() => {
    if (visible && ref.current) heights.set(key, ref.current.offsetHeight);
  });
  return (
    <div ref={ref} class="vblock" data-block={index} style={visible ? undefined : { height: `${heights.get(key) ?? estimate(entries)}px` }}>
      {visible && entries.map(render)}
    </div>
  );
}

function useWindowedBlocks(blocks: Entry[][], container: { current: HTMLElement | null }) {
  // The first two blocks render synchronously so the first paint already has rows.
  const [visible, setVisible] = useState<Set<number>>(() => new Set([0, 1]));
  useEffect(() => {
    setVisible(new Set([0, 1]));
    const list = container.current;
    if (!list) return;
    // Observe against the element that scrolls: with the viewport as root, the scroll container
    // clips the look-ahead margin and rows below the fold would render only once visible.
    const scroller = list.closest<HTMLElement>(".content, .pane") ?? null;
    const io = new IntersectionObserver(
      (records) =>
        setVisible((prev) => {
          const next = new Set(prev);
          for (const r of records) {
            const i = Number((r.target as HTMLElement).dataset.block);
            if (r.isIntersecting) next.add(i);
            else next.delete(i);
          }
          return next;
        }),
      { root: scroller, rootMargin: "800px 0px" },
    );
    list.querySelectorAll(".vblock").forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [blocks]);
  return visible;
}

/** A chip that opens a menu when off and clears its filter when on. */
function MenuChip({ selected, icon, label, items, onClear }: { selected: boolean; icon: string; label: string; items: () => MenuItem[]; onClear: () => void }) {
  return (
    <button
      type="button"
      class="chip"
      aria-pressed={selected}
      onClick={(e) => (selected ? onClear() : openMenu(e.currentTarget as HTMLElement, items()))}
    >
      <Icon d={selected ? I.close : icon} size={18} />
      {label}
      {!selected && <Icon d={I.down} size={18} />}
    </button>
  );
}

function FilterChips() {
  const f = filter.value;
  const set = (patch: Partial<Filter>) => (filter.value = { ...filter.value, ...patch });
  const folder = f.folder ? (f.folder === "none" ? "No folder" : folderNames.value.get(f.folder) ?? "Folder") : "Folder";
  const SORTS: Record<SortKey, string> = { name: "Name", modified: "Last modified", created: "Date created", password: "Password changed" };
  const orgLabel = f.collection
    ? aux.value.collections.find((c) => c.id === f.collection)?.name ?? "Collection"
    : f.org === "personal" ? "My vault" : f.org ? orgNames.value.get(f.org) ?? "Organization" : "Organization";
  return (
    <div class="chips" style={{ paddingBottom: "8px" }}>
      {/* Trash and archive are modes, not filters you pick here: show them first so the way out is visible. */}
      {f.trash && <Chip selected closable icon={I.del} onClick={() => set({ trash: false })}>Trash</Chip>}
      {f.archive && <Chip selected closable icon={I.archive} onClick={() => set({ archive: false })}>Archive</Chip>}
      <MenuChip
        selected={f.type != null}
        icon={I.filter}
        label={f.type != null ? TYPE_META[f.type]?.plural : "Type"}
        onClear={() => set({ type: null })}
        items={() => Object.entries(TYPE_META).map(([t, m]) => ({ icon: m.icon, label: m.plural, run: () => set({ type: Number(t) as ItemKind }) }))}
      />
      <Chip selected={!!f.favorites} icon={I.star} onClick={() => set({ favorites: !f.favorites })}>Favorites</Chip>
      <MenuChip
        selected={!!f.folder}
        icon={I.folder}
        label={folder}
        onClear={() => set({ folder: null })}
        items={() => [
          ...aux.value.folders.map((x) => ({ icon: I.folder, label: x.name, run: () => set({ folder: x.id }) })),
          ...(aux.value.folders.length ? [{ divider: true, label: "" }] : []),
          { icon: I.remove, label: "No folder", run: () => set({ folder: "none" }) },
        ]}
      />
      {aux.value.orgs.length > 0 && (
        <MenuChip
          selected={!!(f.org || f.collection)}
          icon={I.group}
          label={orgLabel}
          onClear={() => set({ org: null, collection: null })}
          items={() => [
            { icon: I.person, label: "My vault", run: () => set({ org: "personal" }) },
            ...aux.value.orgs.map((o) => ({ icon: I.group, label: o.name, run: () => set({ org: o.id }) })),
            ...(aux.value.collections.length ? [{ divider: true, label: "" }, { header: true, label: "Collections" }] : []),
            ...aux.value.collections.map((c) => ({ icon: I.inventory, label: c.name, run: () => set({ collection: c.id }) })),
          ]}
        />
      )}
      <Chip selected={!!f.totp} icon={I.timer} onClick={() => set({ totp: !f.totp })}>One-time codes</Chip>
      <Chip selected={!!f.passkeys} icon={I.passkey} onClick={() => set({ passkeys: !f.passkeys })}>Passkeys</Chip>
      <button
        type="button"
        class="chip"
        aria-pressed={sort.value !== "name"}
        onClick={(e) =>
          openMenu(e.currentTarget as HTMLElement, (Object.keys(SORTS) as SortKey[]).map((k) => ({
            icon: k === sort.value ? I.check : I.sort,
            label: SORTS[k],
            run: () => (sort.value = k),
          })))
        }
      >
        <Icon d={I.sort} size={18} />
        {SORTS[sort.value]}
      </button>
    </div>
  );
}

export function SearchBar({ autoFocus, onArrowDown, trailing }: { autoFocus?: boolean; onArrowDown?: () => void; trailing?: JSX.Element }) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (autoFocus) ref.current?.focus();
    const k = (e: KeyboardEvent) => {
      if ((e.key === "/" || (e.key === "f" && (e.ctrlKey || e.metaKey))) && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") {
        e.preventDefault();
        ref.current?.focus();
      }
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, []);
  return (
    <div class="searchbar">
      <Icon d={I.search} />
      <input
        ref={ref}
        type="search"
        placeholder="Search vault"
        aria-label="Search vault"
        value={query.value}
        onInput={(e) => (query.value = e.currentTarget.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape" && query.value) {
            e.preventDefault();
            e.stopPropagation();
            query.value = "";
          } else if (e.key === "ArrowDown") {
            e.preventDefault();
            onArrowDown?.();
          }
        }}
        spellcheck={false}
        autoComplete="off"
      />
      {query.value && <IconButton icon={I.close} label="Clear search" small onClick={() => { query.value = ""; ref.current?.focus(); }} />}
      {trailing}
    </div>
  );
}

export function SyncDot() {
  const st = syncStatus.value;
  if (syncing.value) return <IconButton icon={I.sync} label="Syncing…" class="spin-slow" onClick={() => {}} />;
  if (st && !st.ok)
    return (
      <IconButton
        icon={st.offline ? I.cloudOff : I.error}
        label={st.offline ? "Offline — showing saved data" : `Sync failed: ${st.error}`}
        onClick={() => { void syncNow(true).then(() => syncStatus.value?.ok && toast("Synced", { tone: "ok" })); }}
      />
    );
  return null;
}

export function VaultList({ popup, onOpen, pageMatches, onFill }: { popup?: boolean; onOpen: (s: Summary) => void; pageMatches?: { host: string; matches: PageMatch[] } | null; onFill?: (m: PageMatch) => void }) {
  const list = results.value;
  const listRef = useRef<HTMLDivElement>(null);
  const showSite = popup && pageMatches?.host && !query.value && !Object.values(filter.value).some(Boolean);
  const entries = useMemo(
    () => buildEntries(list, !query.value && sort.value === "name", !filter.value.favorites),
    [list],
  );
  const blocks = useMemo(() => {
    const out: Entry[][] = [];
    for (let i = 0; i < entries.length; i += BLOCK) out.push(entries.slice(i, i + BLOCK));
    return out;
  }, [entries]);
  const heights = useMemo(() => new Map<string, number>(), [entries]);
  const visible = useWindowedBlocks(blocks, listRef);
  const renderEntry = (e: Entry) =>
    e.kind === "label" ? (
      <div key={e.key} class="section-label">{e.text}</div>
    ) : (
      <ItemRow key={e.key} hit={e.hit} onOpen={onOpen} selected={selectedId.value === e.hit.s.id} pos={e.pos} />
    );

  const focusFirst = () => (listRef.current?.querySelector(".item.click") as HTMLElement | null)?.focus();

  return (
    <div class="vault-list" ref={listRef}
      onKeyDown={(e) => {
        const t = e.target as HTMLElement;
        if (!t.classList.contains("item")) return;
        const all = [...(listRef.current?.querySelectorAll<HTMLElement>(".item.click") ?? [])];
        const i = all.indexOf(t);
        if (e.key === "ArrowDown" && i < all.length - 1) { e.preventDefault(); all[i + 1].focus(); }
        if (e.key === "ArrowUp") { e.preventDefault(); if (i > 0) all[i - 1].focus(); else (document.querySelector(".searchbar input") as HTMLElement)?.focus(); }
      }}>
      <div class="list-head">
        {/* In the tab the rail already has the sync tile and the account button. */}
        <SearchBar autoFocus={popup} onArrowDown={focusFirst} trailing={popup ? <><SyncDot /><AccountButton /></> : undefined} />
        <FilterChips />
        {syncing.value && <div class="progress-line" />}
      </div>

      {showSite && (
        <>
          <div class="section-label">{pageMatches.host ? `On ${pageMatches.host}` : "This site"}</div>
          {pageMatches.matches.length ? (
            <div class="group">
              {pageMatches.matches.map((m) => (
                <Row
                  key={m.id}
                  leading={<ItemAvatar s={{ id: m.id, name: m.name, type: m.type as CipherType, uris: m.uri ? [m.uri] : [], fav: m.fav, rp: m.rp, att: false, pk: [] }} />}
                  title={m.name}
                  sub={m.sub}
                  trailing={
                    <>
                      <IconButton icon={I.openInNew} label="View item" small onClick={(e) => { e.stopPropagation(); const s = items.value.get(m.id); s && onOpen(s); }} />
                      <span class="badge" style={{ background: "var(--primary)", color: "var(--on-primary)" }}>Fill</span>
                    </>
                  }
                  onClick={() => onFill?.(m)}
                />
              ))}
            </div>
          ) : (
            <div class="group">
              <Row leading={<Icon d={I.globe} />} title="No logins for this site" sub="Add one, or search below" />
            </div>
          )}
        </>
      )}

      {!vaultLoaded.value || (syncing.value && items.value.size === 0) ? (
        <div style={{ marginTop: "8px" }}>
          <Skeleton rows={7} />
        </div>
      ) : list.length === 0 ? (
        query.value || Object.values(filter.value).some(Boolean) ? (
          <EmptyState text="Nothing found" icon={I.manageSearch} />
        ) : (
          <EmptyState text={items.value.size ? "Nothing here" : "Your vault is empty. Add your first item."} />
        )
      ) : (
        <div class="list-section vlist" data-count={list.length}>
          {blocks.map((b, i) => (
            <Block key={`${i}:${b[0]?.key}`} entries={b} index={i} visible={visible.has(i)} heights={heights} render={renderEntry} />
          ))}
        </div>
      )}
      <div style={{ height: popup ? "88px" : "96px" }} />
    </div>
  );
}

export function newItemMenu(anchor: HTMLElement, prefill?: Record<string, any>) {
  openMenu(anchor, [
    { header: true, label: "New item" },
    ...([CipherType.Login, CipherType.Card, CipherType.Identity, CipherType.SecureNote, CipherType.SshKey, GPG_KIND] as ItemKind[]).map((t) => ({
      icon: TYPE_META[t].icon,
      label: TYPE_META[t].label,
      run: () => push({ name: "edit", type: t, prefill }),
    })),
  ]);
}

export function usePageMatches(enabled: boolean) {
  const [pm, setPm] = useState<{ host: string; matches: PageMatch[]; tabId?: number } | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    // popup.html?tab=<id>: a popup opened as a tab or window (tests, a popped-out popup) fills
    // that tab instead of the active one, which would be itself.
    const tabId = Number(new URLSearchParams(location.search).get("tab")) || undefined;
    const load = () =>
      rpc("autofill.pageMatches", { tabId })
        .then((r) => alive && setPm(r))
        .catch(() => alive && setPm(null));
    void load();
    return () => {
      alive = false;
    };
  }, [enabled, items.value]);
  return pm;
}

