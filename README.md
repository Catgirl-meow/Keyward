# Keyward

A fast Bitwarden-compatible browser extension (built for Vaultwarden) with the look of the
Keyguard Android app. Targets Helium/Chromium and LibreWolf/Firefox on Linux.

## Develop

```sh
npm install
npm run build            # dist/chromium, dist/firefox
npm run dev-server up    # local Vaultwarden on http://localhost:8087 + mailpit on :8025
npm run seed             # test accounts -> tests/.env.test
npm run smoke            # both browsers load the extension and render the popup
npm test                 # unit tests
npm run e2e              # end-to-end against the local server
node tests/e2e/real-server.ts   # small smoke test on pass.catg1rl.com (test account in tests/.env.test)
```

The local server keeps its data on tmpfs: after `npm run dev-server down && npm run dev-server up`
run `npm run seed` again.

Docs: [audit of the official extension](docs/audit-official-extension.md),
[protocol notes](docs/protocol.md), [design tokens](docs/design.md).
