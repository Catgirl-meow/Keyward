# Installing Keyward

Keyward is not in the Chrome Web Store or on addons.mozilla.org. You build the packages from
this repository and install them yourself.

## Build the packages

```sh
npm ci
npm run package
```

This writes three files to `dist/`:

| File | For |
|---|---|
| `keyward-<version>-chromium.zip` | Helium (or any Chromium browser) |
| `keyward-<version>-firefox.xpi` | LibreWolf. It is unsigned; see below for signing. |
| `keyward-source.zip` | The committed source code. Mozilla's review of the minified code needs it. |

`npm run package` also runs `web-ext lint`. Any lint error stops the release. Two warnings are
expected:

- `UNSAFE_VAR_ASSIGNMENT` in a `ui/c-*.js` chunk. It comes from Preact's
  `dangerouslySetInnerHTML` support, which Keyward doesn't use.
- `KEY_FIREFOX_ANDROID_UNSUPPORTED_BY_MIN_VERSION`. Keyward doesn't target Firefox for Android.

## Helium

Chromium browsers don't install `.zip` or `.crx` files from outside the Web Store. Load
Keyward as an unpacked extension instead:

1. Unzip `keyward-<version>-chromium.zip` into a folder you will keep, for example
   `~/.local/share/keyward/chromium`.
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and pick that
   folder.
3. Pin Keyward to the toolbar from the puzzle-piece menu.

**Updating:** unzip the new version over the same folder, then click the reload arrow on
Keyward's card. The extension ID never changes, because the manifest carries a fixed public key.
That keeps the login, settings and offline vault across updates.

## LibreWolf

Keyward needs LibreWolf 140 or later; it is tested on 157. There are two ways to install it.

### Option A: signed by Mozilla (recommended)

Mozilla signs "unlisted" add-ons without publishing them. You need an addons.mozilla.org
account.

1. On addons.mozilla.org, open **Developer Hub → Manage API Keys** and create a key. You get a
   JWT issuer and a secret.
2. Run:

   ```sh
   npm run package
   WEB_EXT_API_KEY=<JWT issuer> WEB_EXT_API_SECRET=<secret> npm run sign:firefox
   ```

   The signed `.xpi` lands in `dist/`. `keyward-source.zip` is uploaded with it, because the
   build is minified.
3. In LibreWolf, open `about:addons`, click the gear menu, choose **Install Add-on From File…**
   and pick the signed `.xpi`.

**Updating:** raise `version` in `package.json`, then package and sign again. Mozilla doesn't
sign the same version twice. Then install the new file the same way.

### Option B: unsigned

LibreWolf is built without Firefox's signing requirement (`MOZ_REQUIRE_SIGNING` is off,
checked on 157.0.1). That means it honours the pref that allows unsigned add-ons:

1. Open `about:config` and set `xpinstall.signatures.required` to `false`.
2. In `about:addons`, click the gear menu, choose **Install Add-on From File…** and pick
   `keyward-<version>-firefox.xpi`.

`tests/e2e/install.test.ts` installs the unsigned package this way and checks two things: that
it loads as a permanent add-on, not a temporary one, and that it works with LibreWolf's default
privacy settings.

### LibreWolf's privacy defaults

- **Clearing cookies and site data at shutdown** (on by default) doesn't touch Keyward. Its
  account, settings and offline vault live in extension storage, which LibreWolf keeps. The
  install test checks this.
- **resistFingerprinting** (on by default) doesn't get in Keyward's way. The install test runs
  with it on.
- **HTTPS-only mode** is fine, since your server uses https.

## First run

1. Click the Keyward button. The server is preset to `KW_DEFAULT_SERVER` from `.env` at build time (`https://vault.bitwarden.com` if unset). To use another
   server, open **Server** on the login screen.
2. Log in with your email and master password, then complete two-step login if your account
   has it (authenticator app, email code or security key).
3. Keyward locks whenever the browser restarts. To unlock with a PIN instead of the master
   password, set one in **Settings → Security**. By default the PIN works only until the
   browser closes. Turning on **Keep PIN unlock after a browser restart** changes that; Keyward
   then warns that a short PIN can be guessed offline by anyone who copies the browser profile.

To check that everything works on your own server and sites, see
[MANUAL-TEST.md](MANUAL-TEST.md).
