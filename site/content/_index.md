---
title: "PPPoEject (CVE-2026-68121) — Linux PPPoE sendmsg use-after-free"
description: "Linux kernel PPPoE sendmsg stale skb-head use-after-free (CVE-2026-68121, PPPoEject) — an unprivileged local user escalates to root through a device-header-callback skb reallocation, with a public exploit — distro patch status tracker"
layout: "single"
date: 2026-09-18
lastmod: 2026-09-22
cover:
  image: "pppoeject-tracker.png"
  alt: "PPPoEject — Linux kernel PPPoE sendmsg stale skb-head use-after-free tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-68121 |
| Alias | `PPPoEject` (the name the [disclosure][writeup] and [PoC][poc] use) |
| Component | Kernel: PPPoE transmit path — `pppoe_sendmsg()` keeps a pointer into the skb head across the lower device's header callback (`drivers/net/ppp/pppoe.c`) |
| Type | Use-after-free write into a freed skb head: a device header callback reallocates the head via `pskb_expand_head()` during `dev_hard_header()`, and the PPPoE header write then lands in freed slab memory |
| Impact | Kernel heap corruption reachable **locally** and weaponised to **local privilege escalation to root** — a public exploit ([`manizada/PPPoEject`][poc]) escalates an unprivileged user to a root shell. Also a repeatable use-after-free that oopses the kernel (**DoS**) |
| Upstream fix | [`e9c238f6fe42`][fix] (*pppoe: reload header pointer after dev_hard_header()*); first in **v7.2-rc5**, backported to **every maintained stable line** (7.1.6 through 5.10.265 — see *Linux kernel* rows below). Reloads the header through the skb network-header offset after the device header is built |
| Introduced | The flaw predates git history — the fix's `Fixes:` tag names [`1da177e4c3f4`][intro] (*Linux-2.6.12-rc2*, 2005). `pppoe_sendmsg()` has cached the header pointer across `dev_hard_header()` for the life of the PPPoE driver, so **essentially every PPPoE-capable kernel is in-window** |
| Affected window | **2.6.12 through 7.1.5** without the backport (and mainline before **v7.2-rc5**). Fixed in **v7.2-rc5** and the 7.1 / 6.18 / 6.12 / 6.6 / 6.1 / 5.15 / 5.10 stable backports — per-branch *First fixed* below |
| Discoverer | Asim Manizada ([@manizada](https://github.com/manizada)) — research, fix, and public exploit |
| Public disclosure | 2026-09-18 ([oss-security][oss], after a linux-distros embargo; reported to `security@kernel.org` mid-July 2026). CVE published by the kernel CNA 2026-08-10 |
| Public PoC | **Yes — a complete working exploit.** [`manizada/PPPoEject`][poc] ships `pppoeject_root_repro.py`, escalating an unprivileged user to a root shell; the author reports it targeting Fedora 44 and Ubuntu 24.04 |
| KEV / EPSS / CVSS | Kernel CNA **CVSS 3.1 7.8 HIGH** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`); Red Hat scores it **7.3 HIGH** (`…/C:H/I:L/A:H`, impact Moderate), differing on the integrity metric. NVD carries the CNA score (status *Received*, no independent analysis yet). Not in KEV; EPSS **~0.14%**. See *Scoring* below |
| Related | One of four local-root kernel bugs disclosed together on 2026-09-18: [DirtyAH6 (CVE-2026-80844)](https://kimmo.cloud/dirtyah6/), [TUNderflow (CVE-2026-81000)](https://kimmo.cloud/tunderflow/), and [DiagSpill (CVE-2026-74469)](https://kimmo.cloud/diagspill/) |
{.summary}

> :warning: **A local root exploit is public and several tracked
> distributions are still unpatched.** The fix ships in every maintained
> upstream stable line (mainline, 7.2, 7.1, 6.18, 6.12, 6.6, 6.1, 5.15,
> and 5.10). Debian's **sid**, **forky**, **trixie**, and **bookworm**
> carry it, all seven tracked NixOS refs have rebased onto the fixed 6.18
> build, and all three Amazon Linux 2023 kernel streams have shipped it.
> **Proxmox VE 9 and the Rocky Linux / RHEL family are still
> vulnerable** at the time of writing — Red Hat has no fix yet for RHEL 8,
> 9, or 10 (only the niche RHEL 8 `kernel-rt` package is marked
> **"Will not fix"**). Treat any host where an unprivileged user or a
> container can reach `CAP_NET_ADMIN` in a namespace as directly exposed,
> and apply the mitigations below until a
> patched kernel is available.

## How the exploitation chain works

`pppoe_sendmsg()` builds a socket buffer, copies the user payload into it,
and then calls `dev_hard_header()` so the lower network device can
construct its link-layer header before PPPoE fills in its own header. The
function saves a pointer to the PPPoE header **before** that call and
reuses it **after** — but a device header callback is allowed to
reallocate the skb head with `pskb_expand_head()`, which frees the old
head and invalidates any pointer into it. The subsequent six-byte header
`memcpy()` and the `ph->length` store then write through that stale
pointer into freed slab memory.

The trigger is a race the attacker drives deliberately. A PPPoE send is
blocked inside `copy_from_user()` on an attacker-owned FUSE page; meanwhile
the first non-Ethernet port — a GRE or IP6GRE device — is added to an
empty **team** (or **bonding**) device. The team's delegated header
callback then expands the skb head, "ejecting" the old head while
`pppoe_sendmsg()` still holds a pointer into it. When the blocked copy
completes, the header write lands in the freed head.

From that use-after-free the public exploit builds a chain to root:

1. **Groom.** An `AF_PACKET` TX-ring carrier is filled with fake
   `struct file` objects, and a populated file-descriptor table is groomed
   into the allocation that will be freed.
2. **Free.** A PPPoE send is stalled on a FUSE page, then a GRE/IP6GRE
   port is added to an empty team (Fedora) or bonding (Ubuntu) device,
   making `dev_hard_header()` reallocate and free the skb head.
3. **Corrupt.** The stale PPPoE header write redirects one live fdtable
   entry to the attacker-built fake `struct file`.
4. **Escalate.** Closing that descriptor runs a controlled kernel
   callback, which installs root credentials and opens `/bin/sh -p`.

The fix, [`e9c238f6fe42`][fix], reloads the PPPoE header through the skb's
network-header offset after `dev_hard_header()` returns —
`pskb_expand_head()` updates that offset when it relocates the head — so
the write always targets the live head.

> :information_source: **Only the kernel backport flips a verdict here.**
> The flaw is entirely in kernel code and the fix is a single commit, so a
> row is *Fixed* only when its kernel carries [`e9c238f6fe42`][fix]. There
> is no not-affected case: the bug predates git history, so every
> supported kernel line is in-window. The reachability conditions
> (unprivileged user namespaces, PPPoE, FUSE, team/bonding + GRE) decide
> *who* can reach an unpatched kernel — they are prose, never a column,
> and never downgrade a verdict.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`1da177e4c3f4`][intro] | Introduced (per `Fixes:`) | *Linux-2.6.12-rc2* (2005) — the start of git history. The stale-pointer pattern in `pppoe_sendmsg()` predates the git era, so the fix's `Fixes:` tag names the epoch commit; there is no later introducing change to point at. |
| [`e9c238f6fe42`][fix] | Fixed | *pppoe: reload header pointer after dev_hard_header()* — reloads `pppoe_hdr(skb)` through the skb network-header offset after the device header is built. First released in **v7.2-rc5**. |

The reachable lifetime therefore spans **2.6.12 through 7.1.5** (and
mainline before v7.2-rc5). A kernel is safe only by carrying the fix.

## Patch status

A row is **Fixed** only if its kernel carries the [`e9c238f6fe42`][fix]
backport — a release at or past its branch's first-fixed version, or an
explicit distro cherry-pick. Every maintained upstream stable line now
carries the fix (see the *Linux kernel* rows), including the **7.2.x**
stable branch, which was cut after the fix had already landed. Debian's
**sid**, **forky**, **trixie**, and **bookworm** have rebased onto it, all
seven tracked NixOS refs default to the fixed 6.18 build, and all three
Amazon Linux 2023 kernel streams have shipped it; **Proxmox VE 9** and
the **Rocky Linux / RHEL** family remain **Vulnerable**.

The first group is the upstream kernel; the rest are a focused set of
x86-64 distributions, with per-distribution detail in the sections that
follow. *Current kernel* is live; *First fixed* and *Fixed since* stay `—`
until a row is fixed.

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.3-rc4 | 7.2-rc5 | 2026-07-26 | :white_check_mark: Fixed — carries `e9c238f6fe42` |
| Linux kernel | 7.2.x | 7.2.7 | 7.2 | 2026-08-16 | :white_check_mark: Fixed |
| Linux kernel | 7.1.x | 7.1.13 (EOL) | 7.1.6 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.18.x | 6.18.53 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.12.x | 6.12.111 | 6.12.101 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.6.x | 6.6.157 | 6.6.148 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.1.x | 6.1.188 | 6.1.183 | 2026-08-19 | :white_check_mark: Fixed |
| Linux kernel | 5.15.x | 5.15.221 | 5.15.216 | 2026-08-19 | :white_check_mark: Fixed |
| Linux kernel | 5.10.x | 5.10.270 | 5.10.265 | 2026-08-19 | :white_check_mark: Fixed |
| Debian | sid (unstable) | 7.2.6-1 | 7.1.6-1 | 2026-08-04 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.13-1 | 7.1.6-1 | 2026-08-17 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.107-1 | 6.12.101-1 | 2026-08-06 | :white_check_mark: Fixed |
| Debian | 12 (bookworm) | 6.1.187-1 | 6.1.187-1 | 2026-09-08 | :white_check_mark: Fixed |
| Proxmox VE | 9 (default) | 7.0.14-19-pve | — | — | :x: Vulnerable |
| NixOS | master | 6.18.53 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | release-26.05 | 6.18.53 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.53 | 6.18.42 | 2026-08-04 | :white_check_mark: Fixed |
| NixOS | Unstable (small) | 6.18.53 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | Unstable (nixpkgs) | 6.18.53 | 6.18.42 | 2026-08-08 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.52 | 6.18.42 | 2026-08-05 | :white_check_mark: Fixed |
| NixOS | 26.05 (small) | 6.18.53 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| Rocky Linux / RHEL | 10 | 6.12.0-211.56.1.el10_2.0.1 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 9 | 5.14.0-687.49.1.el9_8 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 8 | 4.18.0-553.164.1.el8_10 | — | — | :x: Vulnerable — no RHSA yet |
| Amazon Linux | 2023 (default) | 6.1.186-228.376 | 6.1.186-228.374 | 2026-09-14 | :white_check_mark: Fixed — ALAS2023-2026-2143 |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.103-129.197 | 6.12.103-127.188 | 2026-08-31 | :white_check_mark: Fixed — ALAS2023-2026-2110 |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.48-109.150 | 6.18.44-99.149 | 2026-08-31 | :white_check_mark: Fixed — ALAS2023-2026-2106 |
{.distros}

### Linux kernel

The fix reached Linus in **v7.2-rc5** (tagged 2026-07-26). It was
backported the same day it was authored to every maintained stable line,
and the releases followed in two batches: **7.1.6**, **6.18.42**,
**6.12.101**, and **6.6.148** on 2026-08-03, then **6.1.183**,
**5.15.216**, and **5.10.265** on 2026-08-19. A new **7.2.x** stable
branch was later cut from **v7.2** (2026-08-16), which already contained
the fix — so every 7.2.x release carries it. The **7.1.y** line has since
reached end-of-life at **7.1.13**, but every release from 7.1.6 onward
carries the fix, so a host pinned to 7.1.y stays fixed. Every maintained
upstream branch is now fixed; the remaining exposure is entirely at the
distribution layer.

To confirm a tree directly, the fix adds a single `ph = pppoe_hdr(skb);`
reload after the `dev_hard_header(skb, dev, ETH_P_PPP_SES, …)` call in
`pppoe_sendmsg()` (`drivers/net/ppp/pppoe.c`); a tree missing that line is
unpatched.

### Debian

Debian's status splits on which upstream branch each suite tracks. **sid**
reached the fix with the `7.1.6-1` upload (7.1.6 is the 7.1 line's
first-fixed release), first seen in the archive 2026-08-04, and has since
moved on to the 7.2 line — still **fixed**. **forky** (testing, the future
Debian 14) reached the fix on the 7.1 line: it migrated onto a fixed 7.1
kernel on 2026-08-17, so it is **fixed** too.

**trixie** (Debian 13) rides the 6.12 line and shipped `6.12.101-1` — its
line's first-fixed release — as a `trixie-security` update, so it is
**fixed**; the security tracker records the fix. **bookworm** (Debian 12,
the 6.1 line) is **fixed** too: `bookworm-security` published `6.1.187-1`,
repackaging the upstream `6.1.187` release, past the line's `6.1.183`
first fix, first seen in the archive 2026-09-08.

**bullseye** (Debian 11) reached the end of its LTS window on 2026-08-31
and has dropped out of Debian's active security support — it no longer
appears in the security tracker or the archive's package index, so no DSA
for this CVE will reach it. Its last published kernel remains unpatched;
the only way out for a host still on it is to upgrade to a supported
release (bookworm or trixie).

The `pppoe`, `team`, and `bonding` modules Debian ships autoload on demand
and are not blacklisted by default, so a Debian host with unprivileged
user namespaces enabled exposes the unprivileged local path.

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels, so Debian's status does not
carry over; whether a PVE kernel carries the fix tracks its **Ubuntu**
base. **PVE 9**'s default `proxmox-kernel-7.0` is still **vulnerable**:
the packaging carries no named PPPoE cherry-pick, and Ubuntu's security
tracker has not yet released a fixed build for resolute (the 7.0 base),
which is marked *pending*. A PVE 9 build rebased onto a resolute base
that names the fix as released, or a named Proxmox cherry-pick, will
flip PVE 9.

**PVE 8** reached end of life in **August 2026**, before this tracker
existed and before any fix reached its kernels: its default
`proxmox-kernel-6.8` and its opt-in series are permanently
**vulnerable**, and no fix is coming. A host still on PVE 8 should
upgrade to PVE 9.

PVE 9 also publishes older opt-in / preview kernel series
(`proxmox-kernel-6.17`, `-6.14` and the like) that ride equally
unpatched Ubuntu bases; a host booting one of those is vulnerable until it
moves to a fixed kernel.

### NixOS

Every tracked ref's default `linuxPackages` is `linux_6_18`. The 6.18.y
line has a fixed release (6.18.42), and the nixpkgs `master` and
`release-26.05` branches picked it up on 2026-08-03 — both are **fixed**.
The five republishing channels have all picked up the fix as well, each
once its Hydra jobset passed: `nixos-unstable-small` and `nixos-26.05-small`
first (the `-small` channels ride a reduced jobset and typically lead),
then `nixos-unstable`, `nixos-26.05`, and `nixpkgs-unstable`. Every tracked
NixOS ref is now **fixed**. The `nixpkgs-unstable` channel — what a bare
`nixpkgs` flake registry input resolves to — is a separate channel aimed
at Nix users on other operating systems.

A host that overrides `boot.kernelPackages` to an older series
(`linux_6_1` / `linux_5_15` / `linux_5_10`) is fixed only if that series
is at or past its own first-fixed release; the tracked default is the
fixed 6.18 build.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks that carry the vulnerable PPPoE
code. Red Hat's CVE record (CSAF/VEX, initial release 2026-08-10) marks
**RHEL 8, 9, and 10 affected** and ships **no fix** for the base kernel
package on any of them — no RHSA yet. So every in-support EL stream is
**vulnerable**. Red Hat rates the flaw **Moderate**, scoring the integrity
impact lower than the demonstrated local-root exploit (`I:L` versus the
CNA's `I:H`). Rocky rebuilds RHEL unchanged, so its status tracks Red
Hat's; AlmaLinux (typically the fastest rebuild) has published no erratum
either. Oracle Linux and CloudLinux track the RHEL determination.

Unlike some kernel CVEs, this bug has **no not-affected EL base**: the
flaw predates git history, so even EL8's 4.18 kernel is in-window. The
niche `kernel-rt` real-time kernel shares the base kernel's exposure —
RHEL 8's `kernel-rt` is the one package Red Hat has explicitly flagged
**"Will not fix,"** while the base kernel it shares its source with
remains open (no fix planned yet, but not ruled out). Because Red Hat has
no fix for any in-support stream's base kernel, the practical response on
EL hosts is the mitigations below.

### Amazon Linux

Three advisories fixed CVE-2026-68121 across the AL2023 kernel streams:
**ALAS2023-2026-2143** (2026-09-14) in the default `kernel` stream,
**ALAS2023-2026-2110** (2026-08-31) in the `kernel6.12` opt-in stream, and
**ALAS2023-2026-2106** (2026-08-31) in the `kernel6.18` opt-in stream. All
three are **fixed**. Amazon builds carry their own cherry-picks, so a
stream can be fixed at a build below its line's upstream first-fixed
release. Amazon Linux 2 reached end of support on 2026-06-30 and is not
tracked.

## Detection

**Is the running kernel in the affected window and missing the fix?**
Every kernel below its line's first-fixed release is in-window. Compare
the running kernel against the *Patch status* table's *First fixed* column
for its series:

```bash
uname -r
```

**Can an unprivileged user reach `CAP_NET_ADMIN`?** The unprivileged local
path needs unprivileged user namespaces. If either of these is non-zero,
an ordinary user can `unshare -Urn` into a namespace where it holds
`CAP_NET_ADMIN`:

```bash
sysctl kernel.unprivileged_userns_clone user.max_user_namespaces
```

**Are the modules the trigger needs available?** The chain needs PPPoE, a
team or bonding device, a GRE/IP6GRE lower device, and FUSE. `modinfo`
prints the on-disk path of each named module (an error for any absent):

```bash
modinfo -F filename pppoe team bonding ip_gre ip6_gre fuse
```

**Is this a multi-tenant or container host?** Any context where an
unprivileged user, or a container holding `CAP_NET_ADMIN` (for example one
run with `--cap-add=NET_ADMIN` or a privileged pod), can configure network
devices is directly exposed, regardless of the user-namespace sysctls:

```bash
grep -rEl 'CAP_NET_ADMIN|NET_ADMIN|privileged' /etc/containers /etc/kubernetes 2>/dev/null
```

## Public PoC

There **is** a public working exploit. [`manizada/PPPoEject`][poc] ships
`pppoeject_root_repro.py`, a self-contained program that escalates an
unprivileged user to a root shell by driving the PPPoE race and the chain
described above. The author reports it targeting Fedora 44
(`6.19.10-300.fc44`, via a team device) and Ubuntu 24.04
(`6.8.0-124`/`-136-generic`, via a bonding chain). Do **not** run it on a
system you are not authorised to test — the author warns it is
destructive and should run only in a disposable VM.

The exploit needs a fairly specific environment — x86-64 with RDTSCP and
KPTI/PTI inactive, at least four logical CPUs, read/write access to
`/dev/fuse`, unprivileged user **and** network namespaces with
`CAP_NET_ADMIN` and `CAP_NET_RAW`, and PPPoE / IP6GRE / AF_PACKET / team
(Fedora) or bonding (Ubuntu) support — but those are ordinary defaults on
many desktop and server kernels. A working exploit being public means this
should be treated as exploited-in-practice: patch or apply the mitigations
below.

## Mitigation

The real fix is a patched kernel (a release at or past **v7.2-rc5** /
**7.1.6**, or a distro backport of [`e9c238f6fe42`][fix]). Until one is
installed, the exposure can be narrowed — none of these is a fix.

### Restrict unprivileged user namespaces

The unprivileged local path depends on user namespaces to obtain
`CAP_NET_ADMIN`. Where unprivileged user namespaces are not needed,
disabling them closes that path (it does **not** stop a process or
container that already holds `CAP_NET_ADMIN`). On Debian/Ubuntu kernels:

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=0
```

Persist it across reboots:

```bash
echo 'kernel.unprivileged_userns_clone = 0' | sudo tee /etc/sysctl.d/99-cve-2026-68121.conf
```

On kernels without that Debian/Ubuntu knob, cap the count instead:

```bash
sudo sysctl -w user.max_user_namespaces=0
```

### Block the PPPoE module

Where PPPoE is not used, blocking the module removes the vulnerable
send path. `install … /bin/false` is surer than a plain `blacklist`, which
only suppresses alias autoloading:

```bash
printf 'install pppoe /bin/false\n' | sudo tee /etc/modprobe.d/cve-2026-68121.conf
```

That rule only prevents *future* autoload — it does not remove a module
already resident. Where `pppoe` is loaded but idle, unload it so the block
takes effect now:

```bash
sudo modprobe -r pppoe
```

The disclosure cautions that blocking PoC-specific modules is not a proper
mitigation on its own — the underlying flaw is in `pppoe_sendmsg()`, and
other device-callback paths could reach it — so treat this as a stopgap
where PPPoE is genuinely unused, and patch as soon as possible.

### Restrict who holds CAP_NET_ADMIN

On multi-tenant and container hosts, review which workloads are granted
`CAP_NET_ADMIN`: drop it from container capability sets that do not need
it, avoid privileged containers, and keep untrusted workloads out of
namespaces where they can configure network devices. This shrinks the
reachable surface but leaves a trusted-but-hostile caller in scope.

## Risk notes

- **Multi-tenant and container hosts are the exposure.** The demonstrated
  impact is local privilege escalation to root, so any host where an
  unprivileged user or a container can reach `CAP_NET_ADMIN` and configure
  network devices is directly in scope — a public exploit exists.
- **Several distributions remain unpatched.** The fix reaches every
  maintained upstream stable line, and Debian, all tracked NixOS refs, and
  Amazon Linux 2023 have adopted it, but both Proxmox VE releases and the
  Rocky Linux / RHEL family are still vulnerable. Check the *First fixed*
  column, not the kernel's age.
- **Red Hat has no fix for the in-support streams.** RHEL 8, 9, and 10 all
  have no RHSA for the base kernel (only RHEL 8's niche `kernel-rt` is
  marked "Will not fix"), so EL hosts should rely on the mitigations rather
  than waiting for an erratum.
- **Part of a set of four.** PPPoEject was disclosed alongside
  [DirtyAH6](https://kimmo.cloud/dirtyah6/),
  [TUNderflow](https://kimmo.cloud/tunderflow/), and
  [DiagSpill](https://kimmo.cloud/diagspill/); a host exposed to one is
  often exposed to the others. The first stable releases carrying all four
  fixes are 5.10.270, 5.15.221, 6.1.188, 6.6.157, 6.12.109, 6.18.50, and
  7.2.4.

## Verification log

Every verdict in the table above is backed by a checkable source. This log
records the provenance — the git reference, advisory, or repository index
that established each fact — so any row can be audited or reproduced. Most
readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- The fix is `e9c238f6fe42fb1b4dba3a578277de32cb487937` (*pppoe: reload
  header pointer after dev_hard_header()*), first released in **v7.2-rc5**
  (`git describe --contains` → `v7.2-rc5~27^2~32`, tag date 2026-07-26,
  via `~/src/linux/stable`). It adds a single `ph = pppoe_hdr(skb)` reload
  after `dev_hard_header()` in `pppoe_sendmsg()`.
- The flaw predates git history: the commit's `Fixes:` tag names
  `1da177e4c3f4` (*Linux-2.6.12-rc2*, 2005), the epoch of the git era, so
  there is no in-window not-affected branch.
- **CVE-2026-68121** assigned by the kernel CNA (confirmed via `vulns.git`
  `origin/master`, `cve/published/2026/CVE-2026-68121.{json,dyad,cvss}`;
  record keys on `e9c238f6fe42fb1b4dba3a578277de32cb487937`, published
  2026-08-10). The `.dyad` lists a vulnerable:fixed pair for every
  maintained line: `2.6.12 → 5.10.265`, `→ 5.15.216`, `→ 6.1.183`,
  `→ 6.6.148`, `→ 6.12.101`, `→ 6.18.42`, `→ 7.1.6`, and `→ 7.2`.
- **Stable backports** (subject grep against `~/src/linux/stable`, each
  bounded to the branch's own history):
  - `linux-7.1.y`: `bed4caecd723`, released **7.1.6** (tag date
    2026-08-03). The branch has since reached end-of-life at **7.1.13**
    (2026-09-02), which carries the fix.
  - `linux-6.18.y`: `6866abf59976`, released **6.18.42** (2026-08-03).
  - `linux-6.12.y`: `7e9fbd7f96bc`, released **6.12.101** (2026-08-03).
  - `linux-6.6.y`: `e6493a4d1ee1`, released **6.6.148** (2026-08-03).
  - `linux-6.1.y`: `ba3409369c54`, released **6.1.183** (2026-08-19).
  - `linux-5.15.y`: `6eed5ae7887a`, released **5.15.216** (2026-08-19).
  - `linux-5.10.y`: `7a56e7c9b08e`, released **5.10.265** (2026-08-19).
- A **7.2.x** stable branch (`origin/linux-7.2.y`) exists; its base tag
  `v7.2` (2026-08-16) already contains `e9c238f6fe42`, so every 7.2.x
  release carries the fix without a separate cherry-pick.
- The Ubuntu feed cites `6.8.y`, `6.17.y`, and `7.0.y` as "released"
  alongside `7.2-rc5`; a direct read of `pppoe.c` on those branches'
  final releases (`origin/linux-6.8.y`, `-6.17.y`, `-7.0.y`, all EOL)
  shows none carries the `ph = pppoe_hdr(skb)` reload, so they are not
  read as a fix path for the Proxmox rows.
- The `Linux kernel` rows' *Current kernel* cells are read from
  kernel.org's `finger_banner`.

#### Scoring

- **Kernel CNA** (`vulns.git` `.cvss`/`.json`, `origin/master`): CVSS 3.1
  **7.8 HIGH** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`). `AV:L`
  because the trigger is the local `sendmsg()` syscall on a PF_PPPOX
  socket, not remote reception; `PR:L` because a PPPoE socket needs no
  privilege and the team/GRE topology is reachable with `CAP_NET_ADMIN`
  in an unprivileged user namespace.
- **Red Hat** (CSAF/VEX, initial release 2026-08-10, current revision 3 /
  2026-09-18): CVSS 3.1 **7.3 HIGH** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H`),
  impact **Moderate** — the same local vantage, scoring integrity `I:L`
  rather than the CNA's `I:H`. Base-`kernel` remediation is
  `none_available` ("Affected") for RHEL 6/7/8/9/10 (no not-affected EL
  base); only RHEL 8's niche `kernel-rt` carries `no_fix_planned` ("Will
  not fix"). No `vendor_fix` / RHSA for any stream.
- **NVD / EPSS / KEV**: NVD record status *Received* (its CVSS 3.1 mirrors
  the CNA score rather than an independent assessment); no CWE assigned.
  EPSS **~0.14%** (~4th percentile, via api.first.org); not in CISA KEV.

#### Distributions

- **Debian** (security tracker `data/json`, `linux` source package,
  `scope: local`):
  - sid resolved *fixed*; the tracker's fixed version for unstable is
    `7.1.6-1` (the 7.1 branch's first-fixed release), first seen in the
    archive 2026-08-04 per snapshot.debian.org.
  - forky (testing) resolved *fixed* (fixed_version `7.1.6-1`); the suite
    migrated onto a fixed 7.1 kernel on 2026-08-17.
  - trixie resolved *fixed*; fixed_version `6.12.101-1` (the 6.12 branch's
    first-fixed release), present in both `trixie` and `trixie-security`,
    first seen in the archive 2026-08-06 per snapshot.debian.org.
  - bookworm resolved *fixed*, fixed_version `6.1.187-1`;
    `bookworm-security` published `6.1.187-1` (repacking upstream
    `6.1.187`, past the 6.1 branch's `6.1.183` first fix), first seen in
    the archive 2026-09-08 per snapshot.debian.org.
  - bullseye is no longer in the tracker's `releases` map for `linux` —
    its LTS window closed 2026-08-31, and `madison?package=linux&s=bullseye`
    returns only the frozen oldoldstable entries.
  - The stable suites' *Current kernel* values are the
    `<suite>-security` entries under the tracker's `repositories`; sid's
    and forky's come from ftp-master madison.
- **Ubuntu** (ubuntu.com/security/cves/CVE-2026-68121.json, used for the
  Proxmox base): `resolute` *pending* (`7.0.0-38.38` named, not yet
  released), `jammy` *pending* (`5.15.0-198.208`), `noble`/`focal`
  *needed*; `bionic`/`xenial`/`trusty` *needed*. The feed's "upstream:
  released" entry cites `7.2~rc5`, `6.8.y`, `6.17.y`, and `7.0.y`; a direct
  `pppoe.c` read (above) shows the three frozen branches do not carry the
  fix, so this is not read as a Proxmox fix path.
- **Proxmox VE** (`~/src/proxmox/pve-kernel`, pve-no-subscription
  `Packages.gz`): the default series is `proxmox-kernel-7.0` (PVE 9,
  trixie); the *Current kernel* build is read from pve-no-subscription
  `Packages.gz`.
  - PVE 9: the newest published build rebased onto Ubuntu-7.0.0-38.38
    (`origin/master` changelog); its `debian/changelog`
    names no PPPoE cherry-pick of its own. Ubuntu's own packaging
    changelog for `7.0.0-38.38` (changelogs.ubuntu.com) does carry the fix
    — it lists `CVE-2026-68121` with the `pppoe: reload header pointer
    after dev_hard_header()` subject — but Ubuntu's CVE tracker still
    marks resolute's `7.0.0-38.38` *pending*, i.e. not yet released to the
    archive. Vulnerable until Ubuntu marks that build *released* (PVE has
    already rebased onto its source) or PVE names its own cherry-pick.
  - PVE 8 reached end of life in 2026-08 (Proxmox VE FAQ lifecycle
    table, pve.proxmox.com/wiki/FAQ), before this tracker existed.
  - `origin/bookworm-6.8`'s changelog named no PPPoE cherry-pick and
    its `patches/kernel/` held no `pppoe` patch at the final build.
  - Ubuntu marks the 6.8 (noble) kernel *needed*.
- **NixOS** (`~/src/nixos/nixpkgs`): `packageAliases.linux_default =
  linux_6_18` at every tracked ref. The `master` and `release-26.05`
  branches bumped to the fixed **6.18.42** on 2026-08-03 (`git log -S` on
  `kernels-org.json`, commits `b658e06342e8` / `33565191d37a`) — both rows
  are fixed. Each channel's *Fixed since* is resolved via
  `scripts/nixos-first-shipped <channel> <bump-commit>`:
  `nixos-unstable-small` 2026-08-03, `nixos-unstable` 2026-08-04,
  `nixpkgs-unstable` 2026-08-08 (all from the master bump), and
  `nixos-26.05-small` 2026-08-03, `nixos-26.05` 2026-08-05 (from the
  release-26.05 bump). Each row's *Current kernel* is the `6.18` version
  `kernels-org.json` resolves at that ref (branch refs from the clone,
  channels via their `git-revision` pins).
- **Rocky / RHEL family**: Red Hat's CSAF/VEX record
  (`security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-68121.json`,
  current revision 3 / 2026-09-18) marks RHEL 6/7/8/9/10 `known_affected`
  with remediation `none_available` ("Affected") for the base `kernel`
  package on every one of them — no `vendor_fix`, no RHSA. Only RHEL 8's
  niche `kernel-rt` package carries `no_fix_planned` ("Will not fix"); the
  initial 2026-08-10 release had applied that same "Will not fix" to RHEL
  8's base kernel too, narrowed to just `kernel-rt` by revision 3. The
  Rocky rows' *Current kernel* NVRs are read from BaseOS
  repodata (`primary.xml.gz`, highest `rel`). No AlmaLinux erratum (OSV,
  errata.json).
- **Amazon Linux** (AL2023 `updateinfo.xml.gz` / `primary.xml.gz`,
  `x86_64` mirror, via `scripts/alas-cve`): CVE-2026-68121 appears in
  three advisories — **ALAS2023-2026-2143** (Important, 2026-09-14) fixing
  the default `kernel` stream at `6.1.186-228.374.amzn2023`,
  **ALAS2023-2026-2110** (Important, 2026-08-31) fixing `kernel6.12` at
  `6.12.103-127.188.amzn2023`, and **ALAS2023-2026-2106** (Important,
  2026-08-31) fixing `kernel6.18` at `6.18.44-99.149.amzn2023`. Per-stream
  *Current kernel* values are read from `primary.xml.gz` (highest
  `ver`/`rel`). AL2 is EOL (2026-06-30) and untracked.
{{< /details >}}

## References

| Source | URL |
|---|---|
| Public PoC (A. Manizada) | <https://github.com/manizada/PPPoEject> |
| Disclosure write-up | <https://heyitsas.im/posts/lpe-quartet/> |
| oss-security announcement | <https://www.openwall.com/lists/oss-security/2026/09/18/3> |
| Kernel fix (v7.2-rc5) | <https://git.kernel.org/stable/c/e9c238f6fe42fb1b4dba3a578277de32cb487937> |
| Stable backport (7.1.6) | <https://git.kernel.org/stable/c/bed4caecd723693f750e13adbb2c42ca1249a3fd> |
| CVE-2026-68121 | <https://www.cve.org/CVERecord?id=CVE-2026-68121> |
| NVD entry | <https://nvd.nist.gov/vuln/detail/CVE-2026-68121> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-68121> |
| Ubuntu CVE tracker | <https://ubuntu.com/security/CVE-2026-68121> |
| Red Hat security data | <https://access.redhat.com/security/cve/CVE-2026-68121> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
| DirtyAH6 tracker (CVE-2026-80844) | <https://kimmo.cloud/dirtyah6/> |
| TUNderflow tracker (CVE-2026-81000) | <https://kimmo.cloud/tunderflow/> |
| DiagSpill tracker (CVE-2026-74469) | <https://kimmo.cloud/diagspill/> |
{.references}

[poc]: https://github.com/manizada/PPPoEject
[writeup]: https://heyitsas.im/posts/lpe-quartet/
[oss]: https://www.openwall.com/lists/oss-security/2026/09/18/3
[fix]: https://git.kernel.org/stable/c/e9c238f6fe42fb1b4dba3a578277de32cb487937
[fix-stable]: https://git.kernel.org/stable/c/bed4caecd723693f750e13adbb2c42ca1249a3fd
[intro]: https://git.kernel.org/stable/c/1da177e4c3f41524e886b7f1b8a0c1fc7321cac2
