# Manual test checklist

The automated tests (`npm test`, `npm run e2e`) run against a local Vaultwarden and fixture
pages. This list covers what only you can check: your server, your account, your phone and the
sites you actually use. Do it in Helium and in LibreWolf.

Try a test account on your server first, then your real account. Tick an item only when
you saw the expected result. If something goes wrong, note the browser, the site and what
happened.

## 1. Install and log in

- [ ] Install Keyward as described in [INSTALL.md](INSTALL.md). The toolbar button opens a
      400×600 popup.
- [ ] Log in with your email and master password. The vault shows the same item count as the
      web vault.
- [ ] Two-step login, once with each method your account has:
  - [ ] Authenticator app: the code is accepted.
  - [ ] Email: the code arrives and is accepted.
  - [ ] Security key or passkey: Keyward opens a tab on your server and the browser asks
        for the key; the tab closes once you confirm. A key registered before the server's
        domain fix (2026-10-15) no longer works. Log in another way and register it again in
        the web vault.
- [ ] **Remember this device** on the two-step screen: the next login on this browser skips the second
      step.

## 2. Lock and unlock

- [ ] Restart the browser. Keyward shows "Vault is locked", and the master password unlocks it.
- [ ] Set a PIN (Settings → Security), lock from the account menu and unlock with the PIN. Five
      wrong PINs remove the PIN.
- [ ] Turn on **Keep PIN unlock after a browser restart**, restart, and unlock with the PIN.
- [ ] Set a lock timeout (for example 1 minute), wait, and check it locked.

## 3. Your vault on other devices

- [ ] Create a login in Keyward. It appears on your phone (Keyguard or the Bitwarden app) after
      a sync, with the same username, password and website.
- [ ] Edit that login on the phone. Keyward shows the change after **Sync now** (or within 5
      minutes).
- [ ] Edit the same item on both sides without syncing between the edits. Keyward keeps your
      edit as a copy and says so; nothing is lost.
- [ ] Attachments: add a file in Keyward and open it on the phone, then the reverse.
- [ ] Family organization (if you have one): items in its collections show and can be edited
      when your role allows.

## 4. Autofill

- [ ] **mailfence.com**: log in with the inline menu or Ctrl+Shift+L. On the two-step page that
      follows, Keyward fills the six code boxes from the same item, or copies the code if it
      can't fill them.
- [ ] Shortcuts: Settings → Autofill lists the keys Keyward actually has. A browser gives a key
      to the first extension that asks, so with the official Bitwarden extension installed,
      Ctrl+Shift+L may be Bitwarden's; Settings then says so and **Change shortcuts** opens the
      browser's shortcut page.
- [ ] **Fill on page load** (Settings → Autofill, off by default): on a site with exactly one
      login, the form fills by itself, also when the page draws it late (Proxmox) or after an
      in-page navigation (Monkeytype).
- [ ] Your usual sites, in a list you keep:

  | Site | Login page fills | Two-step code | Notes |
  |---|---|---|---|
  |  |  |  |  |

- [ ] A site where username and password are on separate pages: both steps fill from one
      choice.
- [ ] A login inside a frame (some banks, Microsoft and Google embeds): Keyward asks before
      filling a frame from another site.
- [ ] The inline menu opens from the key icon in the field or with the ↓ key, and never covers
      the page's own controls. Clicking a login in it fills (also on a screen with scaling),
      and it follows the dark theme in LibreWolf too.
- [ ] Save prompt: sign up or log in somewhere new. Keyward offers to save once, after the page
      moves on, and never while you are still typing.
- [ ] Update prompt: change a password on a site. Keyward offers to update the existing item.
- [ ] No prompt on sites you excluded (Settings → Autofill → Excluded sites).
- [ ] Context menu (right-click in a field): fill, copy username/password/code, generate.
- [ ] Cards and identities fill on a checkout or address form.
- [ ] HTTP basic-auth dialogs (for example a router page) fill when that setting is on.

## 5. Passkeys

- [ ] On https://webauthn.io, register a passkey. Keyward's dialog saves it to an item.
- [ ] Sign in to webauthn.io with it.
- [ ] The passkey works from the Bitwarden app or Keyguard on the phone too (on sites that
      accept synced passkeys).
- [ ] **Use browser or security key instead** hands the request to the browser.

## 6. Send, Watchtower, generator

- [ ] Create a text Send with a password. Open the link in a private window, enter the password
      and check the text.
- [ ] Create a file Send and download it from the link. In the popup, **Choose a file** moves
      the Send to the full tab (a file dialog would close the popup) with what you typed kept;
      pick the file there.
- [ ] Popup closes mid-edit: start a new item, switch to another window (the popup closes),
      open Keyward again. The form is back as you left it. Locking throws it away.
- [ ] Watchtower: the local checks run as soon as it opens, and the popup stays responsive
      while they run. The breach check (Have I Been Pwned) and the two-step check
      (2fa.directory) run only when you start them. **Duplicate websites** lists logins with
      two websites where one already covers the other.
- [ ] Watchtower again: close the popup and reopen it. The report (breach and two-step
      results included) is back at once, without checking the vault again. Change a password
      and the report updates; once the breach check has run, the new password is looked up
      on its own.
- [ ] Generator: a password, a passphrase, and a forwarded alias if you use SimpleLogin or
      addy.io.

## 7. SSH and GPG keys

- [ ] Generate an SSH key item. Its public key works in `~/.ssh/authorized_keys` on a test
      host, and the item shows on the phone.
- [ ] Generate a GPG key item (New item → GPG key). It shows as a GPG key in Keyguard on the
      phone.
- [ ] A GPG key you made in Keyguard shows in Keyward as a GPG key, with the right fingerprint.
- [ ] GPG tools (Settings → GPG tools, or the rail in the full tab):
  - [ ] Sign a text; `gpg --verify` on the desktop accepts it once you imported the public key.
  - [ ] Decrypt a message encrypted to that key with `gpg --encrypt`.

## 8. Import and export

- [ ] Export the vault as an encrypted JSON (Settings → Export vault). The file opens in
      Bitwarden's import (web vault → Tools → Import into a test account).
- [ ] Import a browser's password CSV into a test account. The logins arrive with their
      websites.

## 9. Speed and weight

- [ ] The popup opens without a visible delay, even right after the browser starts.
- [ ] Heavy pages (news sites, web apps) don't get slower with Keyward on. Compare against
      the browser with Keyward off.
- [ ] `about:processes` (LibreWolf) or the browser's task manager (Helium): Keyward uses a few
      MB, not hundreds.
