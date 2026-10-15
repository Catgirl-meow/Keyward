# Design tokens (Keyguard look)

Taken from the Keyguard Android app (AChep/keyguard-app) so Keyward feels like it.

## Surfaces

| Role | Dark | Light |
|---|---|---|
| surface / lowest | `#141616` | `#FFFFFF` |
| container low | `#1B1B1B` | `#FAFAFA` |
| container | `#202121` | `#F5F5F5` |
| container high | `#2B2B2C` | `#EEF0F0` |
| container highest | `#363636` | `#DEE0E1` |

AMOLED: surfaces go to `#000`, rows stay `#1B1B1B`.

## Color

- Accent: one of 17 Material 500 swatches (plus a default); only the accent roles come from
  `SchemeVibrant`. Generated at build time by `scripts/gen-theme.ts` into `palettes.gen.ts`; the
  current accent's roles are cached in `localStorage` so the first paint has them.
- Item avatar color: hue = (FNV-1a-32(id) % 60) × 6°, `hsv(h, 0.8, 0.8)`.
- Semantic colors (ok, warning, info, error) as fixed HSV pairs per theme.
- Passwords: digits blue, symbols red.

## Shape and type

- Radii 4 / 8 / 12 / 16 / 28.
- Grouped lists: rows with 16 px outer and 4 px inner corners, 3 px gaps, 16 × 10 px padding.
- Avatars 36 px with 12 px corners; favicon (via the server's `/icons/`) or initials; badges for
  passkey, attachment, reprompt.
- Roboto (variable, latin + latin-ext + cyrillic subsets) and Roboto Mono for secrets.
- Icons: Material Symbols Outlined, filled when selected, inlined as SVG paths at build time.

## Motion

Slide 1/8 of the width plus fade, 300 ms, `cubic-bezier(.6, 0, .4, 1)`; disabled under
`prefers-reduced-motion`.

## Layouts

- Popup 400 × 600: bottom bar (Vault, Generator, Send, Watchtower, Settings).
- Tab: navigation rail with a New button, sync tile and account; vault in two panes (list | detail)
  from 840 px wide, single column below.
