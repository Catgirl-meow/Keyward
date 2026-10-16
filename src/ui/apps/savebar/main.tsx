// Save / update prompt, shown in an iframe at the top right of the page after a login form was
// submitted. The decision (save, update, nothing) was made by the background.
import "../../theme/base.css";
import "../../components/kit.css";
import "../menu/menu.css";
import "./savebar.css";
import { render } from "preact";
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { listen, rpc, type RpcRes } from "../../../platform/messages.ts";
import { loadSettings } from "../../../platform/settings.ts";
import { Button, Icon, IconButton, Select } from "../../components/kit.tsx";
import * as I from "../../icons/index.ts";
import { applyCachedTheme, applyTheme } from "../../theme/theme.ts";
import { overlayChannel, overlayToken } from "../../data/overlay-token.ts";

applyCachedTheme();
type Ctx = RpcRes<"save.ctx">;

function SaveBar() {
  const [ctx, setCtx] = useState<Ctx | null>(null);
  const [folder, setFolder] = useState("");
  const [busy, setBusy] = useState(false);
  const port = useRef<MessagePort | null>(null);
  const root = useRef<HTMLDivElement>(null);

  async function load() {
    const token = await overlayToken;
    const [c, s, dark] = await Promise.all([rpc("save.ctx", { token }), loadSettings(), rpc("ui.dark").catch(() => null)]);
    applyTheme(s, dark);
    port.current ??= (await overlayChannel).port; // before the render that reports the size
    setCtx(c);
  }
  useEffect(() => {
    void load();
    return listen((m) => m.kind === "lock" && void load());
  }, []);
  useLayoutEffect(() => {
    port.current?.postMessage({ t: "size", h: root.current?.offsetHeight ?? 0 });
  });

  async function act(action: "save" | "update" | "never" | "dismiss") {
    setBusy(true);
    try {
      await rpc("save.decide", { token: await overlayToken, action, folderId: folder || null });
    } finally {
      setBusy(false);
      port.current?.postMessage({ t: "close" });
    }
  }

  if (!ctx) return <div ref={root} />;
  if (ctx.kind === "none") {
    port.current?.postMessage({ t: "close" });
    return <div ref={root} />;
  }
  const title = ctx.kind === "update" ? "Update password?" : ctx.kind === "locked" ? "Save this login?" : "Save login?";
  const what =
    ctx.kind === "update" ? (
      <>
        New password for <b>{ctx.itemName}</b>
        {ctx.username ? ` (${ctx.username})` : ""}
      </>
    ) : (
      <>
        {ctx.username ? <b>{ctx.username}</b> : "A password"} on {ctx.host}
      </>
    );
  return (
    <div ref={root} class="kwm kws" role="dialog" aria-label={title}>
      <div class="kws-top">
        <div class="kwm-ico"><Icon d={ctx.kind === "update" ? I.password : I.passkey} size={20} /></div>
        <div class="text">
          <div class="title">{title}</div>
          <div class="sub">{what}</div>
        </div>
        <IconButton icon={I.close} label="Not now" small onClick={() => void act("dismiss")} />
      </div>
      {ctx.kind === "save" && ctx.folders && ctx.folders.length > 0 && (
        <div class="kws-folder">
          <Select label="Folder" value={folder} onChange={setFolder} options={[["", "No folder"], ...ctx.folders.map((f) => [f.id, f.name] as [string, string])]} />
        </div>
      )}
      <div class="kws-actions">
        {ctx.kind === "locked" ? (
          <Button
            onClick={async () => {
              try {
                await chrome.action.openPopup();
              } catch {
                await rpc("ui.openPopup").catch(() => {});
              }
            }}
          >
            Unlock to save
          </Button>
        ) : (
          <>
            {ctx.kind === "save" && (
              <Button variant="text" disabled={busy} onClick={() => void act("never")}>
                Never for this site
              </Button>
            )}
            <Button loading={busy} onClick={() => void act(ctx.kind === "update" ? "update" : "save")}>
              {ctx.kind === "update" ? "Update" : "Save"}
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

render(<SaveBar />, document.getElementById("app")!);
