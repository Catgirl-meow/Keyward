// Generates manifest.json per browser. Kept in code (not JSON files) so both targets share one source.
export type Target = "chromium" | "firefox";

// Stable extension id for Chromium (test fixtures, users' allow-lists). Public key only.
export const CHROMIUM_KEY_FILE = "manifest/chromium-key.pub.b64";

export function manifest(target: Target, version: string, chromiumKey: string | null): Record<string, any> {
  const m: Record<string, any> = {
    manifest_version: 3,
    name: "Keyward",
    short_name: "Keyward",
    description: "Fast Bitwarden-compatible password manager for Vaultwarden, in the style of Keyguard.",
    version,
    icons: { 16: "icons/16.png", 32: "icons/32.png", 48: "icons/48.png", 128: "icons/128.png" },
    action: {
      default_popup: "popup.html",
      default_title: "Keyward",
      default_icon: { 16: "icons/16.png", 32: "icons/32.png" },
    },
    permissions: [
      "storage",
      "unlimitedStorage",
      "alarms",
      "idle",
      "tabs",
      "scripting",
      "contextMenus",
      "webNavigation",
      "webRequest",
      "clipboardWrite",
      "clipboardRead",
      "notifications",
    ],
    host_permissions: ["<all_urls>"],
    content_scripts: [
      {
        matches: ["<all_urls>"],
        js: ["cs/boot.js"],
        run_at: "document_idle",
        all_frames: true,
        match_about_blank: true,
        match_origin_as_fallback: true,
      },
    ],
    commands: {
      _execute_action: { suggested_key: { default: "Ctrl+Shift+Y", linux: "Ctrl+Shift+U" }, description: "Open Keyward" },
      autofill_login: { suggested_key: { default: "Ctrl+Shift+L" }, description: "Autofill login (press again for the next match)" },
      generate_password: { suggested_key: { default: "Ctrl+Shift+9" }, description: "Generate and copy a password" },
      lock_vault: { description: "Lock the vault" },
      autofill_card: { description: "Autofill card" },
      autofill_identity: { description: "Autofill identity" },
    },
    web_accessible_resources: [
      {
        resources: ["menu.html", "savebar.html", "passkey.html", "ui/*", "fonts/*"],
        matches: ["<all_urls>"],
      },
    ],
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; img-src 'self' data: https: http://127.0.0.1:* http://localhost:*; connect-src https: http://127.0.0.1:* http://localhost:* wss: ws://127.0.0.1:* ws://localhost:*",
    },
  };

  if (target === "chromium") {
    m.minimum_chrome_version = "130";
    m.background = { service_worker: "bg.js" };
    m.permissions.push("offscreen", "webRequestAuthProvider");
    m.web_accessible_resources[0].use_dynamic_url = true;
    if (chromiumKey) m.key = chromiumKey;
  } else {
    m.background = { scripts: ["bg.js"] };
    m.permissions.push("webRequestBlocking");
    m.browser_specific_settings = {
      gecko: {
        id: "keyward@catg1rl.com",
        strict_min_version: "140.0",
        data_collection_permissions: { required: ["none"] },
      },
    };
  }
  return m;
}
