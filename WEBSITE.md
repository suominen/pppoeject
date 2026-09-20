# Website plan — `https://kimmo.cloud/pppoeject/`

Publish the PPPoEject tracker as a single-page static site, generated
by **Hugo** locally and rsync'd to a personal nginx server (`haig`).  The
build infrastructure mirrors the sibling kernel trackers (cloned from
CVE-2026-68138); only the content and a few config strings differ.

## Architecture

- **Source repo:** `github.com/suominen/pppoeject` (this repo).
- **Generator:** Hugo ≥ 0.146.0 (standard edition). Run locally; nothing
  built in CI.
- **Source layout:** Hugo project under `site/`.  The tracker is a single
  page at `site/content/_index.md`.
- **Theme:** PaperMod, integrated as a Hugo Module (no submodule).
- **Dev environment:** Nix flake (`flake.nix`) provides everything the
  build, banner, publish, and lookup recipes call (Claude Code itself
  excepted). Auto-activates via `.envrc` with direnv.
- **Build:** `make build` → `hugo --minify --gc --cleanDestinationDir`,
  output in `site/public/`.
- **Publish:** `make dist` → `rsync -avz --delete site/public/` →
  `haig:/pppoeject/`.
- **Web server:** existing nginx vhost on `kimmo.cloud` serves
  `htdocs/pppoeject/` directly at the URL path `/pppoeject/`.

## Naming — nickname slug

The bug has a nickname — **PPPoEject** — from the disclosure and PoC, so
the site uses `pppoeject` as its slug everywhere, matching the three
sibling trackers' repo/URL names.  Following the nickname-slug precedent
(sctphantom, cifswitch, januscape), the slug is lowercase throughout and
the CVE is carried in the title, Summary, and body.

- repo / GitHub / URL / Go module path: `~/src/pppoeject`,
  `github.com/suominen/pppoeject`, `https://kimmo.cloud/pppoeject/`,
  `github.com/suominen/pppoeject/site`
- systemd units and the banner basename: `pppoeject-tracker-update.{service,timer}`,
  `pppoeject-tracker.{svg,png}`

No redirect is needed; the slug never moves.

## Companion trackers

PPPoEject is one of **four** local-root kernel bugs disclosed together on
2026-09-18 by Asim Manizada ([oss-security][oss], [write-up][writeup]).
The other three are tracked separately and cross-linked from this
tracker's Summary *Related* row, Risk notes, and References table:

- **DirtyAH6** — CVE-2026-80844, IPv6 AH routing-header OOB
  (`7bad4bda74dc`) — `/dirtyah6/`.
- **TUNderflow** — CVE-2026-81000, TUN receive-headroom underflow
  (`447c9303942c`) — `/tunderflow/`.
- **DiagSpill** — CVE-2026-74469, SCTP `sctp_diag` transport-count
  overflow (`bd0e9289e264`) — `/diagspill/`.

The first stable releases carrying all four fixes are 5.10.270, 5.15.221,
6.1.188, 6.6.157, 6.12.109, 6.18.50, and 7.2.4.

[oss]: https://www.openwall.com/lists/oss-security/2026/09/18/3
[writeup]: https://heyitsas.im/posts/lpe-quartet/

## Tracker content

- One kernel bug, **single verdict axis**: the `e9c238f6fe42` /
  `bed4caecd723` fix (mainline v7.2-rc5, stable 7.1.6 and every other
  maintained line) is the only thing that flips a row.  There is no
  userspace component that ships as its own package.
- The reachability gate — a PPPoE socket, unprivileged user namespaces (to
  obtain namespaced `CAP_NET_ADMIN`), the team/bonding + GRE trigger
  devices and FUSE, and ≥ 4 CPUs — decides *who* can reach an unpatched
  kernel; it is recorded in prose, **not** as columns, and does **not**
  downgrade a verdict (an affected, unpatched kernel is `:x:` regardless of
  a host's `kernel.unprivileged_userns_clone` setting).
- **Predates git history, so no not-affected branch.**  The fix's `Fixes:`
  tag names the 2.6.12 epoch (`1da177e4c3f4`); the stale-pointer pattern
  has been in `pppoe_sendmsg()` for the life of the driver.  Every
  supported kernel line is in-window, so `:heavy_minus_sign: Not affected`
  never appears — Red Hat marks even RHEL 6/7 `known_affected`.
- **Two CVSS vantages, both local.**  The kernel CNA scores it CVSS 3.1
  **7.8 HIGH** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`); Red Hat scores it
  **7.3 HIGH** (`…/C:H/I:L/A:H`, impact Moderate), differing on the
  integrity metric.  NVD carries the CNA score (status *Received*).
- **Public PoC.**  `manizada/PPPoEject` ships a complete working
  `pppoeject_root_repro.py` escalating an unprivileged user to a root
  shell — so the Public PoC section says so plainly, and Mitigation/Risk
  notes treat a working exploit as available, not hypothetical.
- **Patch status** uses a single **combined table** for upstream and distros
  (`Distribution | Release | Current kernel | First fixed | Fixed since |
  Status`): the upstream kernel is the first `Linux kernel` group; opt-in
  kernels (Amazon alternate series) are their own rows; per-distro `###`
  headings are retained only where there is an audience-relevant note.
  *Current kernel* is live; *First fixed* / *Fixed since* are sticky.  In
  the browser the Distribution column renders as full-width group heading
  rows.  This adopts the merged-table layout folded into
  `~/src/cve-tracker-template`.
- Rows seed `:white_check_mark:` where a fixed release or source-confirmed
  backport is present (every upstream line, Debian, all NixOS refs, Amazon
  Linux 2023) and `:x:` where an in-window kernel is unpatched (Proxmox VE
  8/9, Rocky/RHEL).  No `:heavy_minus_sign:` rows — the bug predates git
  history.  No unconfirmed "fixed" claims.
- Social/OpenGraph banner — `site/assets/pppoeject-tracker.svg`
  rasterised to `site/static/pppoeject-tracker.png` by `make banner`
  (resvg), wired into the `cover:` front-matter.

## Steps

### 1. Hugo project — cloned from CVE-2026-68138

The Hugo skeleton, theme integration, PaperMod overrides, CSS, i18n, and
the merged-table auto-update tooling were cloned wholesale from the
CVE-2026-68138 tracker (the newest live kernel-networking sibling, already
wired to the netdev `net` tree) on 2026-09-18.  Only `baseURL`, `title`,
the Go module path, the banner, the systemd unit names, the timer slot,
and the rsync destination were retargeted, and the content + CLAUDE.md +
auto-update prompt were rewritten for this bug.  The auto-update agent
already reads `~/src/linux/net`, where networking fixes land, so no
subsystem-tree swap was needed.

### 2. Publish

- [ ] First `make build` and inspect `site/public/` locally.
- [ ] First `make dist` to push to `haig` — `htdocs/pppoeject/` created
      (let rsync make it).
- [ ] Verify the site renders at `https://kimmo.cloud/pppoeject/`,
      including the RSS feed and OG metadata.

### 3. Automated maintenance

- [ ] `git worktree add -b auto-update ~/src/auto-update/pppoeject main`
- [ ] Install and enable
      `systemd/pppoeject-tracker-update.{service,timer}` as user units
      (see CLAUDE.md for the exact `ln -sr` + `systemctl --user` recipe).
- [ ] Confirm the timer slot `06,18:50` does not collide with the live
      set (`systemctl --user list-timers | grep tracker`); the three
      companion trackers seeded the same day take their own free slots.

## Decisions

- **Hosting:** own nginx on `haig`, *not* GitHub Pages.  Same as the
  sibling trackers.
- **URL:** `https://kimmo.cloud/pppoeject/` (nickname slug; see "Naming").
- **Theme integration:** Hugo Modules; theme PaperMod.
- **Canonical source:** `site/content/_index.md`.
- **In-window handling:** the flaw predates git history, so every supported
  kernel line is in-window and there is no `:heavy_minus_sign:` row.  By
  seed the fix had reached every maintained upstream stable line, so the
  open exposure is entirely at the distribution layer (Proxmox VE 8/9,
  Rocky/RHEL).
- **Automated maintenance:** a user-level systemd timer
  (`systemd/pppoeject-tracker-update.timer`, twice daily) runs
  `scripts/auto-update`, which merges `origin/main` into a dedicated
  long-lived `auto-update` branch in a separate worktree and hands off to
  headless Claude with `scripts/auto-update-prompt.txt`.  The agent only
  commits onto `auto-update` — it does not push or open PRs.  Merges of
  `auto-update` into `main` are done manually.  The wrapper prints a
  `PPPoEject tracker auto-update starting …` banner as its first
  output line so aggregated syslog can tell the trackers apart.

## Risks & gotchas

- **Anchor drift.** Hugo/Goldmark's heading slugger differs from GitHub's
  for headings with em dashes, parens, plus signs, or slashes.  Pin brittle
  headings with `### Heading {#stable-id}` if external bookmarks need to
  survive renames.
- **Subpath baseURL.** `baseURL = "https://kimmo.cloud/pppoeject/"` must
  include the trailing slash and the path component.
- **`.cleanDestinationDir`** wipes `site/public/` before each build.
- **rsync `--delete`** removes server-side files not present in the build
  output.  Don't store unrelated content under `htdocs/pppoeject/`.
- **Client-side table tweaks.** `layouts/partials/extend_footer.html`
  rewrites tables in the browser: in the `.distros` table it replaces
  the Distribution column with full-width group heading rows (one per
  distribution; Markdown can't express colspan, so the source keeps a
  plain column); other tables get consecutive duplicate first-column
  cells collapsed via `rowSpan`; status-emoji cells are tagged so
  `custom.css` can hang-indent them.  With JavaScript disabled the
  tweaks are skipped — the table still renders correctly, with the
  Distribution column visible and repeated.

## Social banner

The OpenGraph / social-preview image is generated from an SVG source:
`site/assets/pppoeject-tracker.svg` (1200×630) is rasterised to
`site/static/pppoeject-tracker.png` by `make banner`, which runs
`resvg`.  The PNG is committed so ordinary `make build` / `make dist` runs
need no rasteriser.  `resvg` needs the Roboto fonts (`fonts-roboto-unhinted`
on Debian) — without them it silently drops the SVG's sans-serif text.

## Known gaps

- [ ] **Favicons.** PaperMod's `head.html` emits five icon `<link>` tags
      that 404 unless the icon files exist in `site/static/`.  The sibling
      trackers have the same open item.

## Out of scope

- Search and multi-page navigation.  (RSS and the dark/light toggle are
  already wired up.)
