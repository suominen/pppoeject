# PPPoEject (CVE-2026-68121) Tracking — Claude Code Context

This repository contains a living tracking document for **PPPoEject**
(**CVE-2026-68121**), a **use-after-free** in the Linux kernel **PPPoE**
transmit path (`drivers/net/ppp/pppoe.c`).  `pppoe_sendmsg()` saves a
pointer to the PPPoE header (`ph = pppoe_hdr(skb)`) **before** calling
`dev_hard_header()`, then reuses it **after**.  A lower device's header
callback is allowed to reallocate the skb head with `pskb_expand_head()`
during `dev_hard_header()`, freeing the old head — so the subsequent
six-byte header `memcpy()` and the `ph->length` store write through the
stale pointer into freed slab memory.  The trigger: block a PPPoE send in
`copy_from_user()` on an attacker-owned FUSE page, then add the first
non-Ethernet (GRE/IP6GRE) port to an empty **team** (Fedora) or
**bonding** (Ubuntu) device, whose delegated header callback expands the
head.  Impact: a repeatable use-after-free that oopses the kernel
(**DoS**) and, per the public exploit, **local privilege escalation to
root**.

The canonical fix is [`e9c238f6fe42`][fix] (*pppoe: reload header pointer
after dev_hard_header()*), first released in **v7.2-rc5** and backported to
every maintained stable line (7.1.6 as [`bed4caecd723`][fix-stable] down to
5.10.265).  It reloads `pppoe_hdr(skb)` through the skb network-header
offset after the device header is built — `pskb_expand_head()` updates that
offset when it relocates the head.

**This flaw predates git history, so it is NOT a recent regression and
there is NO not-affected branch.**  The stale-pointer pattern has been in
`pppoe_sendmsg()` for the life of the PPPoE driver; the fix's `Fixes:` tag
names [`1da177e4c3f4`][intro] (*Linux-2.6.12-rc2*, 2005), the epoch of the
git era.  Two consequences drive the tracker:

- Every maintained mainline line (5.10, 5.15, 6.1, 6.6, 6.12, 6.18, 7.1,
  7.2) below its branch's first-fixed release is **in-window**.
- **`:heavy_minus_sign: Not affected` never applies here.**  No supported
  kernel predates the bug — Red Hat marks even RHEL 6/7 `known_affected`.
  A row is `:white_check_mark:` only by carrying the fix, and `:x:`
  otherwise; never rate a row not-affected.

**CVE-2026-68121** is assigned by the kernel CNA and published 2026-08-10;
the nickname, write-up, and PoC went public 2026-09-18 06:00 UTC after a
linux-distros embargo (reported to `security@kernel.org` mid-July).
Discovered by **Asim Manizada** ([@manizada](https://github.com/manizada)),
who authored the fix and published a **complete working exploit**
(`pppoeject_root_repro.py`, escalating an unprivileged user to a root
shell) at <https://github.com/manizada/PPPoEject>.  Treat this as
exploited-in-practice.

Reaching the bug needs, as **reachability** (prose, not a verdict axis):

- **A PPPoE socket** — creatable without privilege — and the `pppoe`
  module (autoloads on demand; not blacklisted by default).
- **`CAP_NET_ADMIN` in a network namespace** to configure the
  team/bonding + GRE topology.  An unprivileged user obtains it via
  `unshare -Urn` **where unprivileged user namespaces are enabled**
  (`kernel.unprivileged_userns_clone` / `user.max_user_namespaces > 0`); a
  process or container already holding `CAP_NET_ADMIN` reaches it directly.
- **The trigger devices** — a `team` or `bonding` device, a GRE/IP6GRE
  lower device, and **FUSE** to stall the payload copy — all autoload on
  demand.
- **≥ 4 CPUs** for the public exploit's timing-critical workers.

These are reachability conditions, not verdict axes — an affected,
unpatched kernel is `:x:` regardless of a host's user-namespace posture.

Two CVSS vantages exist, both **local** (`AV:L`).  The kernel CNA scores
it CVSS 3.1 **7.8 HIGH** (`…/C:H/I:H/A:H`); Red Hat scores it **7.3 HIGH**
(`…/C:H/I:L/A:H`, impact Moderate), differing on the integrity metric.
Both belong in the Summary / the `#### Scoring` verification-log subsection.

PPPoEject is one of **four** local-root kernel bugs disclosed together on
2026-09-18 by the same researcher; cross-reference the sibling trackers
(DirtyAH6 / CVE-2026-80844 at `/dirtyah6/`, TUNderflow / CVE-2026-81000 at
`/tunderflow/`, DiagSpill / CVE-2026-74469 at `/diagspill/`) in the
Summary *Related* row, the Risk notes, and the References table.  The first
stable releases carrying all four fixes are 5.10.270, 5.15.221, 6.1.188,
6.6.157, 6.12.109, 6.18.50, and 7.2.4.

The rendered site is published at <https://kimmo.cloud/pppoeject/>.

[fix]: https://git.kernel.org/stable/c/e9c238f6fe42fb1b4dba3a578277de32cb487937
[fix-stable]: https://git.kernel.org/stable/c/bed4caecd723693f750e13adbb2c42ca1249a3fd
[intro]: https://git.kernel.org/stable/c/1da177e4c3f41524e886b7f1b8a0c1fc7321cac2
[poc]: https://github.com/manizada/PPPoEject

## Your task

Keep `site/content/_index.md` (the canonical tracker) up to date as the
kernel fix is picked up by distro kernels.  After edits, rebuild with
`make build` and publish with `make dist`.

A scheduled background agent runs against this repo to refresh the tracker
on its own.  If you find the file has been edited since you last looked,
that's likely why — re-read before assuming stale state.

To retire (archive) this tracker — when every tracked distribution has
shipped a fix, or the bug is otherwise no longer worth active tracking —
follow `~/src/cve-tracker-template/LIFECYCLE.md` § "Retiring a tracker".

## Repo layout

```
.
├── site/                                     # Hugo project
│   ├── content/_index.md                     # the tracker — single source of truth
│   ├── hugo.toml                             # config (subpath baseURL — don't break)
│   ├── assets/css/extended/custom.css        # CSS overrides (PaperMod extension point)
│   ├── layouts/partials/post_meta.html       # overrides PaperMod: adds labels + lastmod
│   └── go.mod, go.sum                        # Hugo Modules — pulls PaperMod theme
├── scripts/                                  # auto-update agent: prompt + driver
│   ├── auto-update                           # wrapper invoked by the systemd timer
│   ├── auto-update-prompt.txt                # prompt fed to headless Claude
│   ├── alas-cve                              # CVE -> AL2023 advisories + fixed NVRs
│   └── nixos-first-shipped                   # channel + commit -> first-published date
├── tests/                                    # helper tests: `make check`
├── systemd/                                  # user-level timer + service units
│   ├── pppoeject-tracker-update.service    # runs scripts/auto-update
│   └── pppoeject-tracker-update.timer      # twice daily
├── flake.nix, .envrc                         # Nix dev shell: hugo + go + git
├── Makefile                                  # `make build`, `make dist`, `make check`, `make banner`
├── LICENSE                                   # CC BY 4.0
├── README.md                                 # user-facing project README
├── WEBSITE.md                                # publication plan / decisions log
└── CLAUDE.md                                 # this file
```

## The tracker file (`site/content/_index.md`) — important constraints

- It has Hugo front-matter with these required fields: `title`,
  `description`, `layout: "single"`, `date` (published), `lastmod` (last
  updated).  Keep all five; the rendering depends on them.
- The H1 has been stripped — Hugo emits the title from front-matter via
  PaperMod's single-post layout.  Don't add an H1 back.
- The TOC is generated by PaperMod's auto-TOC (`ShowToc = true` +
  `UseHugoToc = true` in `hugo.toml`).  Don't add a manual TOC.
- The "Last updated" date lives in the `lastmod` front-matter field.
- **The tracker is for its human readers, not for you.**  Write every
  section for the operator deciding whether their system is exposed —
  the bug, who can reach it, per-distro status, what to do.  Keep out
  anything that only explains how the tracker is *built*: row-inclusion
  policy ("no row", "dead weight", "prose only"), verdict-axis or column
  mechanics ("recorded in prose, not columns", "sticky"), and tracking
  methodology.  Those live here in `CLAUDE.md`; stating them in the
  tracker too duplicates them and drifts.  State the reader-relevant
  *fact* ("the 6.1 line has no backport — vulnerable"), never the policy
  behind it.  In particular, when prose covers a row-less item (a dead
  series, an untracked release), end with the consequence and the way out
  for a host still on it ("no fix is coming — switch to a fixed kernel"),
  never with the row decision ("so it gets no row here").
- **One command per fenced code block, no inline comments.**  Each `bash`
  code fence holds a single command with nothing after it on the line, so
  the rendered copy button yields a clean, runnable command.  Put any
  clarifying note in the prose *before* the block — never as a trailing
  `# ...` comment or a second command in the same fence.

## Update workflow

1. Edit `site/content/_index.md` (or any file under `site/`).
2. Optional: `cd site && hugo server` for a local live preview at
   <http://localhost:1313/pppoeject/>.
3. `make build` — emits to `site/public/` (gitignored).
4. `make dist` — runs `make build`, then rsyncs `site/public/` to
   `haig:/pppoeject/` with `--delete`.

## What flips a verdict — the kernel backport, and only that

This bug lives entirely in the kernel, and the fix is a single commit.  A
row's verdict is one question:

- **Does the kernel carry the [`e9c238f6fe42`][fix] /
  [`bed4caecd723`][fix-stable] fix?**  An in-window kernel at or past
  `v7.2-rc5` / its branch's first-fixed release, or carrying a distro
  backport, is fixed; every other in-window kernel is `:x:`.  This is what
  *Status* and *Fixed since* key on.  At seed every maintained upstream
  stable line already carries the fix (per-branch first-fixed in the
  `Linux kernel` rows), so the remaining `:x:` rows are distro kernels that
  have not yet rebased or cherry-picked — Proxmox VE 8/9 and Rocky/RHEL.
- **`:heavy_minus_sign: Not affected` never applies here.**  The flaw
  predates git history (the fix's `Fixes:` tag names the 2.6.12 epoch), so
  no supported kernel is out-of-window — Red Hat marks even RHEL 6/7
  `known_affected`.  A row is `:white_check_mark:` only by carrying the
  fix, `:x:` otherwise; do not invent a not-affected verdict.

The reachability gate decides *who can reach* an unpatched kernel, but is
**not a verdict axis** — record it in the per-distro `###` prose or the
Summary, never as a column:

- **`CAP_NET_ADMIN` + user namespaces.**  The unprivileged local path needs
  unprivileged user namespaces to obtain namespaced `CAP_NET_ADMIN`
  (`unshare -Urn`), which is used to configure the team/bonding + GRE
  topology; a container or process already holding `CAP_NET_ADMIN` needs
  nothing more.  A host that disables unprivileged user namespaces closes
  the unprivileged path but not the privileged / container one — so it is a
  reach caveat, never a Fixed or a downgrade.
- **A PPPoE socket + the trigger devices.**  The `pppoe`, `team`/`bonding`,
  GRE/IP6GRE, and `fuse` modules autoload on demand and are not
  blacklisted by default on the tracked distributions.

The combined *Patch status* table is the **single source** for every
row's kernel versions, dates, and status — upstream and distros alike.
Columns: `Distribution | Release | Current kernel | First fixed | Fixed
since | Status`.  The upstream kernel is the **first** "distribution" in
the table, labelled `Linux kernel`, one row per branch (`mainline`,
`7.1.x`, … `5.10.x`); its upstream-specific prose lives in the
`### Linux kernel` subsection.  Don't restate the table's columns in
prose or add a parallel per-release table.  The version cells hold
versions only (or `:grey_question:` when unverified) — the verdict lives
in *Status* as the emoji **plus a one-word verdict** and an optional
short note after an em dash (`:white_check_mark: Fixed — carries …`,
`:x: Vulnerable — no ALAS yet`); longer caveats go in the `###` prose.
Label NixOS channels in the **Release** column in friendly form
(`Unstable`, `26.05`).  Where a channel has variants, keep the friendly
base and add the variant in parentheses — `Unstable (small)`,
`Unstable (nixpkgs)`, `26.05 (small)`; this is the one place the
`<release> (<x>)` parenthetical carries something other than a kernel
series, so introduce the real channel name (`nixos-unstable-small`,
`nixpkgs-unstable`) in the `###` prose.  The nixpkgs `master` row is
labelled with the bare branch name, since it is a branch and not a
channel.  Label opt-in/alternate kernel rows by their kernel *series*,
uniformly `<release> (<series> opt-in)` — `2023 (6.12 opt-in)` — and
introduce the underlying package name (`kernel6.12`) in the `###` prose,
never in the Release cell.  Row and list ordering: releases **descending**
within a distribution; within a release the default kernel row first,
then live opt-in/alternate series rows **ascending**, then superseded
(`old`) series rows **descending**.  Rows sharing a Distribution value
must stay contiguous — the browser transform renders each run as one group
heading row.  Keep the `{.distros}` block attribute on the line
**immediately after** the table (no blank line between).

Amazon rows are **one per AL2023 kernel stream** — label the default
stream's row `2023 (default)` (the plain `kernel` package, currently 6.1 —
named in the `### Amazon Linux` prose, not the table) and each opt-in
stream by its series (`2023 (6.12 opt-in)` — the `kernel6.12` package).
Keep every supported stream as its own row, and add a row when Amazon
ships a new stream.  **AL2 has no rows**: it reached end of support on
2026-06-30, before this tracker existed — cover it in one sentence of the
`### Amazon Linux` prose; don't poll AL2 repodata or re-add AL2 rows.

Debian suites get one row for the **default** `linux` kernel and, where
one exists, a separate row per opt-in alternative kernel that ships as
its own source package (a `linux-6.x` rebuild of a newer suite's kernel
for an older suite, as row `12 (6.x opt-in)`); none is tracked at seed.
The `-backports` rebuild of the newer suite's `linux` source belongs in
the `### Debian` prose instead.  **bullseye** (Debian 11) left security
support on 2026-08-31 and gets **no rows** — don't poll it.  The same
default-plus-variant row pattern applies to Proxmox (`proxmox-kernel-*`
series): a default row is labelled plain `9 (default)` — its series is
visible in *Current kernel* and named in the prose — and a former default
or an opt-in overtaken by a newer one is labelled `old` (`9 (6.17 old)`).
Keep an `old` row (hosts still run it), but expect no more updates for it.
A release, stream, or kernel series that was **dead before the tracker
existed** and died *without* the fix gets **no** row at all — its
permanent `:x:` is one sentence in the relevant `###` prose.  Niche
variants (the EL `kernel-rt` real-time kernel) get **no** row — cover them
as a reader-facing note in the `### Rocky Linux / RHEL family` prose.

A per-distro `###` section is for **reader-facing** caveats that don't fit
the table (the reachability gate, EL-family scope).  Keep tracking
methodology out of it — that is agent guidance and belongs in this file.

## Routine run scope — live Current kernel, sticky verdict columns

The **Current kernel** column is **live**: refresh it for **every** row
on every run — upstream point releases and distro package versions
alike — and record any movement.  A Current-kernel bump alone is a real
content change: commit it and bump `lastmod`.  The **verdict columns
are sticky**: *First fixed*, *Fixed since*, and *Status* change **only**
when a row actually flips — its kernel reaches a fixed upstream release
(see the `Linux kernel` rows), **or** the distro ships the
`e9c238f6fe42` / `bed4caecd723` backport / cherry-pick.  A Current-kernel
bump that stays inside the vulnerable window without the backport moves
the *Current kernel* cell and **nothing else**.

**A default-kernel-series switch is always recordable.** PVE moves its
default series during a release's lifetime (`proxmox-default-kernel`
changing which `proxmox-kernel-*` it depends on), and a distro can add
an opt-in series alongside it.  Record a switch in the prose and the
rows: the default row keeps its plain `(default)` label while its
*Current kernel* moves to the new series, the superseded series gets an
`old` row of its own (re-sort: old rows follow the live opt-ins,
descending), a new opt-in series gets a **new row**, and update the
verification log — **together**.  A switch can also flip a verdict on its
own — a newer series may already contain the fix, or may newly be
in-window where the old one was not — so re-derive the verdict rather than
carrying the old one across.

Each run:

- Refresh the `Linux kernel` rows' *Current kernel* from the stable
  point releases (finger_banner; verify backports via
  `~/src/linux/stable`, recipe below).  At seed **every** maintained
  upstream stable line already carries the fix (first-fixed 7.1.6,
  6.18.42, 6.12.101, 6.6.148, 6.1.183, 5.15.216, 5.10.265, plus mainline
  v7.2-rc5 and the 7.2 branch), so these rows are all `:white_check_mark:`
  and only their *Current kernel* moves.  No mainline line is
  "not affected" — the flaw predates git history.
- For a distro row, re-pull the distro's **kernel** version and update
  *Current kernel*.  If an in-window kernel reaches its branch's
  first-fixed release **or** a distro advisory ships the backport ⇒ flip
  *Status* to `:white_check_mark: Fixed`, set *First fixed* to the first
  fixed package build, and set *Fixed since*.
- Watch AlmaLinux (leading indicator) and Rocky/RHEL for the EL rows, and
  Ubuntu for the Proxmox rows.  Note Red Hat's stated **"Will not fix"**
  for RHEL 8 — that row is not expected to flip; RHEL 9/10 have no fix yet
  (`none_available`) but could still gain an RHSA.  For Proxmox, the fix
  can arrive silently in an `update sources to Ubuntu-*` rebase, so
  compare the newest Ubuntu base against Ubuntu's fixed version for that
  series, not just a named cherry-pick.  At seed Ubuntu marks the relevant
  resolute (7.0) and noble (6.8) kernels *pending* / *needed*, so both PVE
  defaults are `:x:`.

`zcat` / `gunzip` **are** in the headless allowlist — use them for the
`Packages.gz` / repodata pulls — as are `grep`, `sort`, `rpmsort`,
`tail`, `jq`, `xq` and `tee`
(`tee` because a `>` redirection into the worktree is refused).  Pull
only kernel versions and advisory state — the tracker records no other
per-distro facts.

**Live versions appear only in the *Patch status* table.**  Never repeat
a row's *Current kernel* value (or any other value the routine run
refreshes — Ubuntu base NVRs, the nixpkgs `linux_7_1` version, the
channel-vs-branch version skew) in the `###` prose or the verification
log.  Prose and log name kernel *series/lines* (`the 6.12 line`) and
sticky facts (first-fixed versions, tag/ship/migration dates) only; a
log entry records the *source and method* for a live value (e.g.
"*Current kernel* read from BaseOS `primary.xml.gz`, highest `rel`"),
never the value itself.  A sticky fact that happens to equal today's
live value stays — it is recorded for the event, not refreshed.  A
routine Current-kernel bump then edits table cells (plus `lastmod`) and
nothing else.

**Never record NixOS channel git-revisions** (the
`channels.nixos.org/<channel>/git-revision` pins) in the tracker.  They
advance on nearly every run — recording them manufactures a diff on an
otherwise no-op run.

## Conventions for status entries

A *Status* cell is the emoji plus its one-word verdict, optionally
followed by an em dash and a short note (advisory ID, `LTS`, `no ALAS
yet`) — longer caveats go in the `###` prose.  **The note must say
something the row's other columns do not.**  Don't restate the verdict
(`Vulnerable — no fix yet` just repeats `Vulnerable`) or the kernel series
(`Vulnerable — 6.1 line` just repeats *Current kernel*); a plain
`:x: Vulnerable` is the norm.  Keep a note only when it adds information —
the awaited advisory (`no RHSA yet`, `no ALAS yet`, `no DSA yet`), a
vendor decision (`RHEL won't fix`), or a non-obvious near-miss:

- `:white_check_mark: Fixed` — a kernel that carries the `e9c238f6fe42` /
  `bed4caecd723` backport (confirmed in changelog / advisory / kernel pin,
  not merely announced): set *First fixed* and *Fixed since*.
- `:heavy_minus_sign: Not affected` — **does not apply to this bug.**  The
  flaw predates git history, so no supported kernel is out-of-window; do
  not use this verdict.
- `:x: Vulnerable` — an in-window kernel without the backport (at seed:
  Proxmox VE 8/9 and the Rocky/RHEL family).
- `:warning: Staged` / `:warning: Mitigated` — not fully resolved: the fix
  is staged but not yet in the user-facing channel (merged / cherry-picked
  but not in a released package), **or** a distro default *materially*
  reduces exposure (e.g. shipping unprivileged user namespaces disabled by
  default).  A mitigation is **not** a fix — it never earns
  `:white_check_mark:`.
- `:grey_question: Unverified` — not yet verified (kernel pin or advisory
  not yet inspected).

### "First fixed" and "Fixed since" columns

Both are **sticky**, set when a row flips to fixed, and stay `—` while
the row is vulnerable or unverified.  *First fixed* is the first release or
package build carrying the fix — from the `.dyad` for the `Linux kernel`
rows, from the advisory / changelog for distro rows.
*Fixed since* is the **first-observation** date the fix first held: the
release tag date for `Linux kernel` rows, the advisory/ship date for
distro rows.  Only touch either if the verdict flips again or the recorded
first-fixed build turns out to have been wrong.

### Verification log

The section has a fixed shape: a short reader-facing intro paragraph
stays **visible**, and the log body is collapsed inside a
`{{< details summary="Full verification log" >}} … {{< /details >}}`
shortcode wrapper (rendered by `site/layouts/shortcodes/details.html`).
Keep the intro and the wrapper intact.  Inside the wrapper the subsections
are `####` headings (h4 — deliberately below the ToC's `endLevel`).
Current subsections are `#### Upstream`, `#### Scoring`, and
`#### Distributions`.

Log entries are **one top-level bullet per source or topic**, opening
with a terse bold lead and the method attribution (e.g. `**Debian**
(via …):`), followed by **one fact per nested sub-bullet** — never run
multiple facts together into a paragraph-bullet.  Sub-bullets follow the
table's ordering conventions (releases descending; within a release the
default kernel first, live opt-in series ascending, then old series
descending).

When you re-verify entries, update the section rather than appending a
line per re-check.  Edit the relevant subsection in place.  Add a new
`####` subsection only when a genuinely new topic appears.  The log
carries no dates of its own — the front-matter `lastmod` is the
document's only recency marker, so do not write verification dates inline.
Method/source attribution *without* a date is fine (e.g.
`(checked against ~/src/linux/stable)`).

The log records **facts**, not run outcomes.  Never write "no change",
"unchanged from prior run", "no verdict changes this run", or similar
prose anywhere in the tracker — an entry that is still accurate reports
that by staying untouched.  This applies just as much on a run that
*does* change something real: update only the lines whose facts changed
and leave every other line exactly as it was.

### Date handling — first-seen / last-changed, not "today"

Dates in the prose (`lastmod`, every "as of <date>" / "released
<date>" / "Fixed since" value) are **first-seen / last-changed** dates,
not "today" dates.  Only move a date when the fact it qualifies actually
changes.  If the entire run is a no-op, leave the file alone and don't
commit at all — don't bump `lastmod`, don't insert "re-confirmed <today>"
parentheticals.

## Build environment

- Hugo **≥ 0.146.0** (PaperMod's minimum); the standard edition
  suffices — no Sass or image processing in this site. Debian apt is
  too old: `go install github.com/gohugoio/hugo@latest`, kept current
  with `gup update` (see `~/src/cve-tracker-template/NEW-TRACKER.md`
  § "Host prerequisites (Debian)").
- Go (any recent version) — for Hugo Modules to pull PaperMod, and to
  build Hugo itself.
- `xq` (Debian package `xq`) on the auto-update host — the Rocky
  changelog cross-check queries `other.xml.gz` with it.
- `rpmsort` (Debian package `rpm`) on the auto-update host — orders
  EL kernel builds by RPM rules for the Rocky rows.
- The Nix flake provides all of these for an interactive shell:
  `nix develop` (or `cd` in if direnv is set up). The timer service
  runs on the host `PATH`, though, so the auto-update host still needs
  the apt packages — the `apt install` line in `NEW-TRACKER.md`
  § "Host prerequisites (Debian)" lists them.
- On this host `nix` is **not** available (Debian, no nixpkgs installed) —
  don't try `nix develop`. Hugo is the `go install` build in `~/go/bin`,
  so plain `make build` / `make dist` work directly.

## Auto-update worktree

The auto-update job works in a dedicated git worktree at
`~/src/auto-update/pppoeject`, checked out on a single long-lived
branch named `auto-update`.  The wrapper merges `origin/main` forward into
that branch on each run, then hands off to headless Claude, which commits
any tracker changes back onto `auto-update` only.  The agent must not
create per-run branches, switch branches, push, or open PRs — merges of
`auto-update` into `main` are done manually by the user.

One-time setup (from the primary checkout at `~/src/pppoeject`):

```
git worktree add -b auto-update ~/src/auto-update/pppoeject main
```

The wrapper runs `git fetch origin` and `git merge origin/main` under
`set -e`, so the repo needs a GitHub `origin` with `main` pushed or every
scheduled run aborts before doing anything.  A freshly `git init`'d tracker
must `git remote add origin https://github.com/suominen/pppoeject.git`
and `git push -u origin main` before the timer is worth enabling.

**The timer runs the wrapper from the primary checkout, not from the
worktree.**  `ExecStart` points at `<primary>/scripts/auto-update`, and the
wrapper reads its prompt from there too, so what executes is always code you
have reviewed and merged to `main`.  The agent can commit to `auto-update`,
so anything under `scripts/`, `.claude/`, `CLAUDE.md`, or `.mcp.json` on
that branch is untrusted: after merging `origin/main` forward the wrapper
refuses to run if any of them differs from `origin/main`, and it refuses
outright if it was invoked from inside the worktree at all.  A wrapper
change therefore takes effect on the next run after you merge it to `main`.

The service unit adds a kernel-level backstop — `ProtectSystem=strict` with
a short `ReadWritePaths` list (the worktree, the `.git` directories git has
to update, and `~/.claude/session-env`, which Claude Code writes on every
Bash call).  Without it the guards above are advisory: the agent may run
`curl`, and `curl -o` writes anywhere this user can, including over the
wrapper the timer runs.  Each repository's `.git/hooks` and `.git/config`
are handed back as `ReadOnlyPaths`, since nothing in a run needs to write
either and both are executable code.

A refusal is a stop-and-look rather than something to clear reflexively —
it means a file that should only ever arrive by merge was rewritten on the
branch.  Inspect it with `git -C ~/src/auto-update/pppoeject diff
origin/main -- scripts .claude CLAUDE.md .mcp.json` before doing anything
else.

To run a refresh immediately (same path the timer takes):

```
systemctl --user start pppoeject-tracker-update.service
```

It is a `oneshot`, so the command blocks until the run finishes; follow its
output with `journalctl --user -u pppoeject-tracker-update`.  Run the
trackers **one at a time**, never in parallel — they share the
`~/src/linux/*` reference clones.

The systemd units ship in `systemd/`.  They are not in a standard unit
search path, so wiring the timer means symlinking both units into
`~/.config/systemd/user/` and then enabling the timer.  Use `ln -sr` so the
links are relative:

```
ln -sr ~/src/pppoeject/systemd/pppoeject-tracker-update.service \
       ~/src/pppoeject/systemd/pppoeject-tracker-update.timer \
       ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now pppoeject-tracker-update.timer
```

The timer fires at `06,18:50` — staggered from the sibling trackers so the
shared `~/src/linux/*` clones are not fetched simultaneously.  Verify the
live set with `systemctl --user list-timers | grep tracker` — this in-doc
list has gone stale before, and three companion trackers (DirtyAH6,
TUNderflow, DiagSpill) were seeded the same day and take their own slots.

## Tearing down the auto-update

To stop the scheduled refresh, unwire it in this order — the sequence
matters, because `systemctl disable` needs the unit definition to still be
resolvable when it runs.

1. **Disable the timer first**, while the unit symlinks are still in place:

   ```
   systemctl --user disable --now pppoeject-tracker-update.timer
   ```

2. **Remove the unit-definition symlinks** from the search path:

   ```
   rm ~/.config/systemd/user/pppoeject-tracker-update.timer \
      ~/.config/systemd/user/pppoeject-tracker-update.service
   ```

3. **Reload** so the running user manager drops the units:

   ```
   systemctl --user daemon-reload
   ```

If the definition symlinks were removed *before* disabling, the stale
`enable` symlink is left behind, parking the timer in a `failed` state.
Recover by deleting it directly, then reloading and clearing the failure:

```
rm ~/.config/systemd/user/timers.target.wants/pppoeject-tracker-update.timer
systemctl --user daemon-reload
systemctl --user reset-failed pppoeject-tracker-update.timer
```

Finally, remove the worktree and its branch (run from
`~/src/pppoeject`):

```
git worktree remove ~/src/auto-update/pppoeject
git branch -d auto-update
```

## Local reference clones

git.kernel.org's cgit HTML pages (any URL ending in /log/, /tree/,
/commit/, etc.) and lore.kernel.org (the mailing-list archive and its
search) are Anubis-gated; WebFetch hits the no-JS challenge and the
auto-update agent cannot read them.  The agent inspects kernel history via
long-living local clones under `~/src/linux/`:

| Clone path           | Upstream                                                           |
|----------------------|--------------------------------------------------------------------|
| `~/src/linux/stable` | `https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git` |
| `~/src/linux/net`    | `git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git`     |
| `~/src/linux/vulns`  | `https://git.kernel.org/pub/scm/linux/security/vulns.git`          |
| `~/src/proxmox/pve-kernel` | `https://git.proxmox.com/git/pve-kernel.git`                 |

`net` is the netdev "net" tree, where networking fixes (the PPPoE driver
among them) land and get tagged for stable before Linus — handy for
confirming a backport's provenance ahead of the stable release.  `vulns`
is the kernel CNA's CVE database.

The auto-update *wrapper* refreshes the clones with `git -C <clone> fetch`
before invoking the headless agent; the agent inspects via the
`origin/<branch>` remote-tracking refs (e.g. `origin/linux-6.12.y`).

**Is a stable branch fixed yet?**  Every mainline line is in-window (the
flaw predates git history), so the question is: does the branch carry the
fix?  The backport is a cherry-pick with a new SHA, so search by the
upstream subject, bounded to the branch's own history:

```
git -C ~/src/linux/stable log v<series>..origin/linux-<series>.y --grep="reload header pointer after dev_hard_header" --format='%h %s'
```

Empty output ⇒ the series is in-window but still **unpatched**
(Vulnerable).  Keep the range bounded to `v<series>..` — an unbounded
subject grep can match an unrelated commit and read as a false result.
**Check the subject of every hit**: a later commit citing the fix SHA in a
`Fixes:` tag also matches, and its backports can land in later point
releases than the real fix.  Prefer the `.dyad` when it covers the branch.
Confirm the fix landed mainline in v7.2-rc5 with:

```
git -C ~/src/linux/stable describe --contains e9c238f6fe42
```

The git smart-HTTP protocol is not Anubis-gated, so `git fetch` /
`git ls-remote` work from any UA.

## The CVE record (`vulns.git`)

**CVE-2026-68121** is already assigned.  The kernel CNA's `vulns.git` keys
each record on the *fixing commit SHA*; inspect via `origin/master`, not
`HEAD` (the wrapper only `git fetch`es):

```
git -C ~/src/linux/vulns show origin/master:cve/published/2026/CVE-2026-68121.dyad
```

The `.dyad` gives the authoritative per-branch `<introduced>:<fixed>`
versions used in the `Linux kernel` rows.  For this bug the **introduced**
side is `2.6.12` (`1da177e4c3f4`, the git epoch) on every pair, and the
**fixed** releases are 5.10.265, 5.15.216, 6.1.183, 6.6.148, 6.12.101,
6.18.42, 7.1.6, and 7.2 — every maintained line has a fixed release, and
no kernel predates the bug.  The `.json` carries the CNA description; the
`.cvss` carries the CNA's CVSS 3.1 7.8 (`AV:L`, `I:H`) vector.  Red Hat's
CVSS 7.3 (`I:L`) score lives in its VEX record.  Watch NVD for an analysed
record / EPSS to add to the Summary.  The repo/site slug stays `pppoeject`
(see `WEBSITE.md`).

## PPPoE reachability — the reach discriminators (prose, not columns)

For an in-window unpatched kernel, whether the bug is reachable at all,
and by whom, turns on:

- **A PPPoE socket.**  Created without privilege; the `pppoe` module
  autoloads on the socket call and is not blacklisted by default.
- **`CAP_NET_ADMIN` reach.**  Configuring the team/bonding + GRE topology
  that drives `dev_hard_header()` head expansion is a non-GET rtnetlink
  operation gated on `CAP_NET_ADMIN`, which is namespace-scoped.  An
  unprivileged local user gets it via `unshare -Urn` **iff unprivileged
  user namespaces are enabled** (`kernel.unprivileged_userns_clone` on
  Debian/Ubuntu, or `user.max_user_namespaces > 0`).  A container run with
  `--cap-add NET_ADMIN` / a privileged pod, or any process already holding
  the cap, reaches it without user namespaces.
- **The trigger devices present.**  A `team` (Fedora) or `bonding`
  (Ubuntu) device, a GRE/IP6GRE lower device, and `fuse` (to stall the
  payload copy) — all autoload on demand and are not blacklisted by
  default on the tracked distributions.
- **≥ 4 CPUs.**  The public exploit's PPPoE sender, fdtable reclaimer,
  FUSE blocker, and trigger-release workers need enough logical CPUs to
  run with little scheduler interference.

These are per-host properties recorded in prose (Summary, Detection,
Mitigation, Risk notes) — re-derive them only when adding a distro or when
a distro reworks its defaults (e.g. shipping unprivileged user namespaces
off by default, which would earn a `:warning: Mitigated` note but never a
Fixed).  They never change a `Status` cell on their own.

## Local nixpkgs clone for NixOS channel verification

*Seeding-and-adoption method.  Do not record the resolved channel
revisions in the tracker.*

NixOS rows are verified from a local nixpkgs clone at `~/src/nixos/nixpkgs`,
not the (JS-rendered, lagging) security-tracker page.  Each channel has a
git-revision pointer at `https://channels.nixos.org/<channel>/git-revision`;
at that commit, `pkgs/os-specific/linux/kernel/kernels-org.json` carries
the version for every supported mainline.org kernel series.  The **default**
`linuxPackages` is set by `packageAliases.linux_default` in
`pkgs/top-level/linux-kernels.nix`.  Read that alias rather than assuming
the default is the newest or oldest LTS.  At seed the default is
`linux_6_18`, whose 6.18.y line has a fixed release (**6.18.42**), so the
tracked default is **Fixed**.  A host that overrides `boot.kernelPackages`
to an older series is fixed only if that series is at or past its own
first-fixed release (`linux_6_1` ≥ 6.1.183, `linux_5_15` ≥ 5.15.216,
`linux_5_10` ≥ 5.10.265).

Tracked refs: the two ungated git branches `master` and `release-26.05`,
plus the five channels `nixos-unstable`, `nixos-unstable-small`,
`nixpkgs-unstable`, `nixos-26.05`, `nixos-26.05-small`.  Rows are ordered
by **propagation**, not by release: the branch a fix lands on first, then
the branch it is backported to, then the channels that republish them,
keeping each `-small` variant next to its sibling.  (This mirrors the
shared tracker template's `DESIGN.md` row-order rule and its
`CLAUDE-package-sources.md` NixOS recipe; keep this section in step.)

The five channels are read from their `git-revision` pins:

```
rev=$(curl -fsSL https://channels.nixos.org/<channel>/git-revision)
git -C ~/src/nixos/nixpkgs show "${rev}:pkgs/os-specific/linux/kernel/kernels-org.json"
```

`channels.nixos.org/<channel>/git-revision` returns a 302 — always pass
`-L` to curl.  The wrapper refreshes the clone on every run.

**The branch rows have no `git-revision` pin** — read them from the
clone's remote-tracking refs instead:

```
git -C ~/src/nixos/nixpkgs show origin/master:pkgs/os-specific/linux/kernel/kernels-org.json
```

A branch row's *Current kernel* tracks the `kernels-org.json` version,
which moves only on a kernel bump.  When a branch's default series first
crosses a fixed release, **a branch row's *Fixed since* is the commit date
of that bump** (nothing publishes an ungated branch); find it with
`git log -S'<version>' … -- …/kernels-org.json`.  **A channel row's *Fixed
since* must be derived, never stamped from the branch date** — resolve it
from the `nix-releases` bucket with the installed helper:

```
~/src/pppoeject/scripts/nixos-first-shipped <channel> <commit>
```

**Invoke it by that absolute primary-checkout path, never as `./scripts/…`
from the auto-update worktree.**  `scripts/` is a guarded path: the agent
can commit to `auto-update`, so the worktree copy is untrusted code, and
the wrapper's guard only compares it against `origin/main` once at
start-up.  Pass the *master* commit for `nixos-unstable`,
`nixos-unstable-small`, and `nixpkgs-unstable`, and the *release-26.05*
commit for `nixos-26.05` and `nixos-26.05-small`.

The three unstable channels are genuinely distinct: `nixos-unstable` is
gated on a full NixOS jobset and can sit days behind `master`,
`nixos-unstable-small` on a reduced jobset and leads, and
`nixpkgs-unstable` is a separate channel — aimed at Nix users on other
operating systems — that a bare `nixpkgs` flake registry input resolves to
by default.  Don't assert a ranking between them beyond what the pins show.

## Proxmox kernel version source

*Seeding-and-adoption method.  The `Packages.gz` index is gzipped; `zcat`
is in the headless allowlist.*

Proxmox ships its **own** Ubuntu-derived kernel (`proxmox-kernel-*`) with a
Debian userland, so the Debian madison feed does not cover it.  Pull the
kernel version from the `pve-no-subscription` `Packages` index.  VE 9 is
trixie-based, VE 8 bookworm-based:

```
url=http://download.proxmox.com/debian/pve/dists/<trixie|bookworm>/pve-no-subscription/binary-amd64/Packages.gz
curl -fsSL "$url" | zcat | grep -A3 '^Package: proxmox-default-kernel'
```

The default kernel *series* is whatever the highest-versioned
`proxmox-default-kernel` meta-package depends on — check it each time.
Every PVE series carries the vulnerable PPPoE code and is in-window, so
each needs the fix to be safe.  At seed **both** maintained series are
unpatched: `proxmox-kernel-7.0` (PVE 9, `7.0.14-17`) and
`proxmox-kernel-6.8` (PVE 8, `6.8.12-43`).

**Two sources — only one is authoritative for the version.** The
*Current kernel* column is the `proxmox-kernel-<series>` build published
in `pve-no-subscription` (read it from the same Packages.gz — the
per-series package entries, highest `rel`).  The pve-kernel **git
changelog leads apt**, so **never copy a changelog version into *Current
kernel***; use the git changelog only to confirm a cherry-pick.  If it
shows the fix cherry-pick in a build `pve-no-subscription` has not yet
published, mark `:warning: Staged`, keep *Current kernel* at the published
version, and flip to `:white_check_mark: Fixed` only when the fixed build
appears in `pve-no-subscription`.

Whether an in-window Proxmox kernel carries the fix tracks its **Ubuntu**
series, not Debian's.  **A named cherry-pick is not the only fix path.**
For a series Ubuntu still maintains, the fix can arrive silently inside an
`update sources to Ubuntu-<base>` rebase, with no CVE-named changelog line.
On every run, for each live in-window series, take the newest `update
sources to Ubuntu-*` base from the changelog and compare it against
Ubuntu's fixed version for that series in the Ubuntu CVE tracker
(`https://ubuntu.com/security/cves/CVE-2026-68121.json` — the
`packages[].statuses[]` entries; `released` + version).  Base ≥ Ubuntu's
fixed version ⇒ the PVE build carries the fix.  Prove it rather than
trusting the version compare: the Ubuntu build's changelog at
`https://changelogs.ubuntu.com/changelogs/pool/main/l/linux/linux_<ver>/changelog`
lists every upstream stable subject it pulled in, so grep it for
`reload header pointer after dev_hard_header` (Launchpad's git `plain`
file URLs return 403 headlessly, so the source itself cannot be read
that way).  At seed Ubuntu marks
resolute (the 7.0 base) *pending* `7.0.0-38.38` — named but not released —
and noble (a 6.8 base) *needed*, so neither PVE default carries the fix;
a *pending* fix is not a released one, so PVE 9 stays `:x:` until the
resolute build is *released* and PVE rebases onto it (or names a
cherry-pick).  To confirm a
cherry-pick, read the packaging changelog / patches in Proxmox's kernel
git from the shared local clone at `~/src/proxmox/pve-kernel` via its
`origin/...` refs:

```
git -C ~/src/proxmox/pve-kernel show origin/master:debian/changelog
```

Branches are named `<debian-suite>-<series>` — `bookworm-6.8`,
`trixie-6.17` — except the newest series on the current suite, which lives
on `master`.  **Don't assume a mapping.** Resolve the series first, then
pick the matching branch:

```
git -C ~/src/proxmox/pve-kernel branch -r
```

The enterprise repository (`enterprise.proxmox.com`) is HTTP-auth-gated,
so track `pve-no-subscription` only — packages flow pvetest →
pve-no-subscription → pve-enterprise, so no-subscription is the leading
indicator.

## Rocky / Amazon kernel version source (RPM repodata)

*Seeding-and-adoption method.  These indexes are gzipped; `zcat` is in the
headless allowlist.*

**For the EL rows, Red Hat's security data is the authoritative leading
signal** — RHEL is upstream of Rocky and AlmaLinux.  At seed Red Hat has
published a **CSAF/VEX record** (initial release 2026-08-10) marking
**RHEL 6/7/8/9/10 `known_affected`** with **no fix** — RHEL 8
`no_fix_planned` ("Will not fix"), RHEL 6/7/9/10 `none_available`
("Affected"), no `vendor_fix` / RHSA.  There is **no `known_not_affected`
EL base** — the flaw predates git history, so even EL6's 2.6.32 carries
it.  So all in-support EL rows are `:x:`; RHEL 8 is not expected to flip,
while RHEL 9/10 could still gain an RHSA.  Read the VEX:

```
curl -fsSL 'https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-68121.json'
```

In the VEX record, `product_status.known_affected` / `known_not_affected`
carry the per-product verdicts and `remediations` the fix state
(`no_fix_planned` = "Will not fix"; a shipped RHSA would appear as a
`vendor_fix` with the fixed kernel NVR).  Cross-check AlmaLinux via OSV
(`https://api.osv.dev/v1/vulns/CVE-2026-68121`) — no ALSA at seed.  The RPM
repodata below gives the current NVR.

Both ship `kernel` as an RPM; pull versions straight from repodata
(`repomd.xml` → the `*-primary.xml.gz` index).  The EL `os/` repos
accumulate every point release's kernel, so pick the highest build
with `rpmsort`, never a plain `sort -V`.

**Highest build: `rpmsort`, never `sort -V`.** Order the `kernel`
`ver`/`rel` pairs from `primary.xml.gz` with `rpmsort` (Debian
package `rpm`; allowlisted for the headless run), which applies
RPM's own comparison — a numeric segment beats an alphabetic one, so
`553.163.1.el8_10` sorts above `553.el8_10`, where a plain `sort -V`
on the raw attribute puts EL8's base build on top.  **Feed it real
`kernel-<epoch>:<ver>-<rel>` strings.** `rpmsort` splits each line
at its last two dashes and compares whatever precedes them as a
package *name* with plain `strcmp`; only the version and release
segments get RPM comparison.  The raw `<version …/>` element has no
dash, so the whole line is a "name" and sorts lexically: on live
Rocky 8 `553.el8_10` lands last and `tail -1` returns the base
build, and on AL2023 lexical order ranks `6.12.95` above `6.12.103`
and `6.18.8` above `6.18.48`.  A bare `ver-rel` is no safer: its
`ver` becomes the "name", which is right only while every line
shares one `ver` (`4.18.9-1.el8` sorts above `4.18.10-1.el8`).  The
epoch goes in front of the version because AL2023 has bumped it
mid-stream (`kernel` and `kernel6.12` carry both `0` and `1`), and
an epoch bump is allowed to reset `ver-rel`; `rpmvercmp` splits on
`:` like on `.`, so `1:6.12.103` outranks `0:6.13.1`.  Build the
string with `jq` (allowlisted; a line without `epoch=`/`ver=`/`rel=`
attributes emits nothing), order with `rpmsort`, take the last line
(`rpmsort` has no reverse flag, hence `tail`, also allowlisted), and
strip the `kernel-<epoch>:` prefix with `grep -o` so what is left
is the `ver-rel` the version cells hold:

```
curl -fsSL "${base}repodata/<hash>-primary.xml.gz" | zcat | grep -A2 '<name>kernel</name>' | grep -o '<version [^>]*>' | jq -R -r 'capture("epoch=\"(?<e>[^\"]+)\"") + capture("ver=\"(?<v>[^\"]+)\"") + capture("rel=\"(?<r>[^\"]+)\"") | "kernel-\(.e):\(.v)-\(.r)"' | rpmsort | tail -1 | grep -o '[^:][^:]*$'
```

Take `<hash>-primary.xml.gz` from the `repomd.xml` href; AL2023's
is the unhashed `repodata/primary.xml.gz`.

- **Rocky** BaseOS: `https://dl.rockylinux.org/pub/rocky/<8|9|10>/BaseOS/x86_64/os`.
  At seed Rocky 8 `4.18.0-553.163.1.el8_10`, Rocky 9
  `5.14.0-687.48.1.el9_8`, Rocky 10 `6.12.0-211.55.1.el10_2` — all
  affected, no RLSA.  Every EL base is in-window (the flaw predates git
  history), so never mark an EL row not-affected on version.

  When an RHSA names a fixed NVR, expect Rocky to **skip the exact RHEL
  NVR** and publish the next build instead, so *First fixed* is the first
  Rocky build past the RHSA NVR, not the RHSA NVR.  For *Fixed since* use
  that build's upload date from the mirror directory listing
  `https://dl.rockylinux.org/pub/rocky/<N>/BaseOS/x86_64/os/Packages/k/`:
  Rocky's own `updateinfo.xml` may name no advisory for the CVE at all,
  and the errata API (`apollo.build.resf.org/api/v3/advisories/`) ignores
  its `?cve=` / `?search=` filters and returns the newest advisories
  whatever is asked, so neither is a usable date source.  OSV lists the
  ALSA when AlmaLinux ships first.

  **Positive changelog cross-check (gated).**  Red Hat rates this CVE
  Moderate impact and may defer the fix for months, so the VEX can stay
  `none_available` while the shipped kernel is what actually matters —
  the backport lands in the kernel RPM `%changelog` before, or without,
  a `vendor_fix` ever appearing, so don't rely on the VEX alone for the
  flip.  **Guardrail:** *Current kernel* is pulled from `primary.xml.gz`
  every run anyway; run this extra check **only when that version
  actually moved for a row still `:x:` / `:warning:`** — never on a
  no-op run, and never for an already-Fixed row.  `other.xml.gz` is a
  large fetch, so gating it on a real version change for an unfixed row
  keeps it off the many quiet runs.  When the gate opens, pull the BaseOS
  `*-other.xml.gz` (resolve its href from `repomd.xml`, same as
  `primary.xml.gz`) and ask it, with an XPath
  query, for the `kernel` changelog entries that name the CVE.  Use `xq`
  (sibprogrammer's Go `xq`, Debian package `xq`; allowlisted for the
  headless run) rather than a line grep: it parses the document, so the
  query does not depend on how createrepo_c happens to serialise it
  (today one node per line; a grep would silently break the day that
  changes).  Each entry's `author` attribute ends in `[<NVR>]`, the RHEL
  build the change landed in, and empty output means no entry names the
  CVE (`xq` exits 0 either way — read the output, not the status):

  ```
  curl -fsSL "${base}repodata/<hash>-other.xml.gz" | zcat | xq -x '//package[@name="kernel"]/changelog[contains(., "CVE-2026-68121")]/@author' | sort -u
  ```

  On a hit, list the shipped Rocky `kernel` builds whose changelog
  carries the entry as `ver-rel`, oldest first — the first line is
  *First fixed* (Rocky may skip the exact RHEL NVR, so it can be later
  than the bracket; the EL `os/` repos keep every build, and a build
  never drops its own newest entries, so the oldest build still
  listing the entry is the first one that shipped it).  The `jq` and
  `grep -o` stages are the ones the highest-build recipe uses, for the
  same reason: `xq -n` prints the raw `<version …/>` element, which
  `rpmsort` would order lexically:

  ```
  curl -fsSL "${base}repodata/<hash>-other.xml.gz" | zcat | xq -n -x '//package[@name="kernel"][changelog[contains(., "CVE-2026-68121")]]/version' | sort -u | jq -R -r 'capture("epoch=\"(?<e>[^\"]+)\"") + capture("ver=\"(?<v>[^\"]+)\"") + capture("rel=\"(?<r>[^\"]+)\"") | "kernel-\(.e):\(.v)-\(.r)"' | rpmsort | grep -o '[^:][^:]*$'
  ```

  Fetch once with `| zcat | tee other.xml` and query the file if you
  want to avoid pulling it twice.  The `kernel` subpackages
  (`kernel-core`, `kernel-modules`, …) share the same changelog, which
  is why the query pins `@name="kernel"`.  A confirmed hit
  means the backport is in the shipped binary: flip the row to Fixed even
  if the VEX still says `none_available`, set *First fixed* to the first
  Rocky build carrying it, and *Fixed since* to that build's upload date
  (the `Packages/k/` listing above).  A **miss is not proof of absence**:
  repodata keeps only the ~10 newest changelog entries per build, so a
  fix that shipped in an older build and scrolled off the tail won't show
  here — but such a fix is already reflected in the VEX `vendor_fix` / an
  RHSA, so the two signals cover each other.  Treat the changelog query as
  the positive early-detector and the VEX as the backstop; neither alone
  is sufficient.
- **Amazon Linux**: the machine-readable ALAS signal is the repodata
  **`updateinfo.xml.gz`** (per-CVE ALAS HTML is JS-rendered, empty
  headlessly).  Resolve the mirror, fetch `<base>repodata/updateinfo.xml.gz`
  and grep the CVE for the ALAS id + fixed `kernel*` NVR; check **all**
  streams (AL2023 `kernel` 6.1, `kernel6.12`, `kernel6.18`), read current
  versions from `primary.xml.gz`, per stream, with the Rocky
  highest-build recipe above (`jq`-built `kernel-<epoch>:<ver>-<rel>`
  strings into `rpmsort`, never the raw element or `sort -V`; the
  epoch matters here, AL2023 has bumped it) and the stream's name in
  the `<name>` grep (`kernel`, `kernel6.12`, `kernel6.18`).
  Mirror:
  `https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list`.
  AL2 is EOL and untracked — no AL2 repodata pulls.  **A CVE-grep miss
  can also mean the mapping is not published yet**, not that no fix
  exists: an ALAS lists only the CVEs known when it was issued, and
  amendments reach the repodata only when Amazon cuts the next
  immutable release snapshot — `mirrors/latest` moves in discrete
  jumps (for OVSwrap's CVE-2026-64531 the cross-reference trailed the
  2026-07-27 advisories by three weeks; the AL2023 default `kernel`
  stream's CVE-2026-68121 fix itself only surfaced in the 2026-09-14
  ALAS2023-2026-2143 mapping).  Amazon also backports fixes
  into builds *below* the series' upstream first-fixed release, so no
  version threshold can flip the row either.  When a kernel-stream
  security ALAS from around the disclosure window ships a build the
  stream has since adopted while the CVE grep still misses, look
  closer before recording "no ALAS".  **`updateinfo.xml` is not
  line-safe — never grep it by line:** it packs the tail of one
  `<update>` entry (references, pkglist) and the head of the next on a
  single physical line, so a line-oriented grep or awk pairs one
  advisory's CVE references with its neighbour's package list — that
  is how ALAS2023-2026-2106 (the `kernel6.18` fix) went unrecorded for
  two weeks.  Use the `scripts/alas-cve` helper, which parses the XML
  and prints one tab-separated line per advisory and kernel stream —
  advisory id, issue date, severity, package, version-release — and
  exits 1 when no advisory names the CVE:

  ```
  curl -fsSL "${base}repodata/updateinfo.xml.gz" | zcat | ~/src/pppoeject/scripts/alas-cve CVE-2026-68121
  ```

  Invoke it by that absolute primary-checkout path, as with
  `nixos-first-shipped` (the worktree copy is untrusted and not
  allowlisted).  `-p <regex>` widens the package filter beyond the
  kernel stream packages.  Its tests live in `tests/` (`make check`).
  The same line-packing applies to `other.xml`, so a changelog
  attribution there needs an XML parse too (interactively, `python3`
  `xml.etree`; no helper covers it yet).

The `kernel-rt` real-time kernel shares the base kernel's exposure and gets
no row — one prose note in `### Rocky Linux / RHEL family` covers it.

## Debian kernel version source

**The security tracker, not a madison base-version compare, is
authoritative for Debian status.** Two traps make a naive version check
wrong: the base suite lags the `-security` upload that ships the fix, and
Debian often backports below the upstream first-fixed release.  Every
Debian kernel is in-window (the flaw predates git history).  At seed the
tracker resolves **all four** tracked suites *fixed*: sid (fixed_version
`7.1.6-1`), forky (`7.1.6-1`), trixie (`6.12.101-1`, present in
`trixie-security`), and bookworm (`6.1.187-1`, via `bookworm-security`).
bullseye left the tracker when its LTS window closed 2026-08-31 — no row.

Read status and fixed version straight from the security tracker:

```
curl -fsSL 'https://security-tracker.debian.org/tracker/data/json'
```

Read the `linux` → `CVE-2026-68121` block: each release's `status`
(resolved/open), the version under `repositories` (a `<suite>-security`
entry = the fix shipped as a security update), and `fixed_version`.  Use
the dak madison API only for the base-suite version and the sid/testing
lineage:

```
curl -fsSL 'https://api.ftp-master.debian.org/madison?package=linux&s=sid,forky,trixie,bookworm&text=on'
```

For a *Fixed since* date, use the `first_seen` of the fixed version in
snapshot.debian.org:

```
curl -fsSL 'https://snapshot.debian.org/mr/package/linux/<version>/srcfiles?fileinfo=1'
```

The `pppoe`, `team`, `bonding`, GRE, and `fuse` modules Debian ships
autoload on demand and are not blacklisted by default, so a Debian host
with unprivileged user namespaces enabled exposes the unprivileged local
path.

## Key sources to monitor

| Source | URL |
|---|---|
| Public PoC (A. Manizada) | <https://github.com/manizada/PPPoEject> |
| Disclosure write-up | <https://heyitsas.im/posts/lpe-quartet/> |
| oss-security announcement | <https://www.openwall.com/lists/oss-security/2026/09/18/3> |
| Kernel fix (v7.2-rc5) | <https://git.kernel.org/stable/c/e9c238f6fe42fb1b4dba3a578277de32cb487937> |
| Stable backport (7.1.6) | <https://git.kernel.org/stable/c/bed4caecd723693f750e13adbb2c42ca1249a3fd> |
| CVE record | <https://www.cve.org/CVERecord?id=CVE-2026-68121> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-68121> |
| Ubuntu CVE tracker (Proxmox base) | <https://ubuntu.com/security/cves/CVE-2026-68121.json> |
| Red Hat security data (CSAF/VEX) | <https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-68121.json> |
| AlmaLinux / OSV | <https://api.osv.dev/v1/vulns/CVE-2026-68121> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
| DirtyAH6 sibling | <https://kimmo.cloud/dirtyah6/> |
| TUNderflow sibling | <https://kimmo.cloud/tunderflow/> |
| DiagSpill sibling | <https://kimmo.cloud/diagspill/> |

For machine-readable data, prefer API/feed endpoints over HTML pages —
several distro sites are JS-rendered SPAs that don't render via WebFetch.

## Platform-specific notes

- **Reachability, not architecture:** the vulnerable code is core PPPoE
  in `drivers/net/ppp/pppoe.c`; what gates it is a PPPoE socket +
  `CAP_NET_ADMIN` reach + the team/bonding/GRE/FUSE trigger devices + ≥ 4
  CPUs, not the CPU type.  Record host posture in prose, never as a column.
  The public exploit is x86-64-specific, but the *vulnerability* is not.
- **EL family (Rocky/RHEL/Alma/Oracle/CloudLinux):** EL8 (4.18), EL9
  (5.14), and EL10 (6.12.0) are `known_affected` and unpatched — RHEL 8 is
  "Will not fix", RHEL 9/10 have no RHSA yet.  There is no not-affected EL
  base (the flaw predates git history), so EL6/EL7 are `known_affected`
  too, but both are EOL and untracked.  AlmaLinux ships ahead of Rocky and
  is the leading indicator for any future fix.
- **Debian / Ubuntu / Proxmox VE:** sid/forky (7.1 line), trixie (6.12),
  and bookworm (6.1) are all fixed; bullseye left the tracker (LTS ended
  2026-08-31).  Both PVE default kernels are in-window and unpatched at
  seed (Ubuntu resolute/noble bases *pending* / *needed*).
- **NixOS:** seven refs are tracked, all defaulting to `linux_6_18`
  (6.18.42+, fixed).  Resolve `linux_default` at each ref separately.
- **Mitigation vs fix:** disabling unprivileged user namespaces
  (`kernel.unprivileged_userns_clone=0` / `user.max_user_namespaces=0`)
  closes the *unprivileged* local path but not a privileged/container
  caller; blocking the `pppoe` module removes the vulnerable send path
  where PPPoE is unused.  Neither is `:white_check_mark:` — the kernel hole
  remains until the backport ships.  A distro that ships unprivileged user
  namespaces off *by default* earns a `:warning: Mitigated` note, not a
  Fixed.

## Known harmless warnings during build

PaperMod's templates still call `.Language.LanguageDirection` and
`.Language.LanguageCode`, which Hugo deprecated in 0.158.0.  The build emits
`WARN deprecated:` lines for both.  Upstream theme issue — don't try to fix
it in this repo.

## License

The tracker content is licensed under **CC BY 4.0** (see `LICENSE` at the
repo root).  Copyright © 2026 Kimmo Suominen.  The site footer credits both
the author and the licence.
