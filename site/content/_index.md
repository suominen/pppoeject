---
title: "PPPoEject (CVE-2026-68121) — Linux PPPoE sendmsg use-after-free"
description: "Linux kernel PPPoE sendmsg stale skb-head use-after-free (CVE-2026-68121, PPPoEject) — an unprivileged local user escalates to root through a device-header-callback skb reallocation, with a public exploit — distro patch status tracker"
layout: "single"
date: 2026-09-18
lastmod: 2026-09-28
cover:
  image: "pppoeject-tracker.png"
  alt: "PPPoEject — Linux kernel PPPoE sendmsg stale skb-head use-after-free tracker"
  hiddenInSingle: true
---

*This tracker is no longer updated.  Every maintained upstream stable
line carries the fix, as do Debian, Proxmox VE 9's default kernel, every
tracked NixOS ref, Rocky Linux / RHEL 10, 9 and 8, and all three Amazon
Linux 2023 kernel streams — install a fixed kernel and reboot into it.*

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
| KEV / EPSS / CVSS | Kernel CNA **CVSS 3.1 7.8 HIGH** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`); Red Hat scores it **7.3 HIGH** (`…/C:H/I:L/A:H`, impact Important), differing on the integrity metric. NVD carries the CNA score (status *Received*, no independent analysis yet). Not in KEV; EPSS **~0.30%**. See *Scoring* below |
| Related | One of four local-root kernel bugs disclosed together on 2026-09-18: [DirtyAH6 (CVE-2026-80844)](https://kimmo.cloud/dirtyah6/), [TUNderflow (CVE-2026-81000)](https://kimmo.cloud/tunderflow/), and [DiagSpill (CVE-2026-74469)](https://kimmo.cloud/diagspill/) |
{.summary}

> :white_check_mark: **A local root exploit is public, and every tracked
> distribution ships a fixed kernel.** The fix ships in every maintained
> upstream stable line (mainline, 7.2, 7.1, 6.18, 6.12, 6.6, 6.1, 5.15,
> and 5.10). Debian's **sid**, **forky**, **trixie**, and **bookworm**
> carry it, all seven tracked NixOS refs have rebased onto the fixed 6.18
> build, and all three Amazon Linux 2023 kernel streams have shipped it.
> Red Hat has shipped fixes for RHEL 8 across its EUS/AUS/E4S
> streams (RHSA-2026:71329 and companions, covering `kernel-rt` too),
> for RHEL 9's current 9.8 stream (RHSA-2026:71700), and for RHEL 10's
> current 10.2 stream (RHSA-2026:71602), and Rocky Linux has
> rebuilt all three fixes. Proxmox VE 9's default kernel carries the fix
> through its Ubuntu base. A host is safe only once it has installed a
> fixed kernel **and rebooted into it**; until then, treat any host where
> an unprivileged user or a container can reach `CAP_NET_ADMIN` in a
> namespace as directly exposed, and apply the mitigations below.

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
Amazon Linux 2023 kernel streams have shipped it. Red Hat has shipped
RHSAs fixing RHEL 8's kernel across its EUS/AUS/E4S streams, RHEL 9's
current 9.8 stream, and RHEL 10's current 10.2 stream, and Rocky Linux
has rebuilt all three fixes. **Proxmox VE 9**'s default kernel carries
the fix through its Ubuntu base.

The first group is the upstream kernel; the rest are a focused set of
x86-64 distributions, with per-distribution detail in the sections that
follow. *Current kernel* is each row's newest build when the tracker was
last updated.

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.3-rc5 | 7.2-rc5 | 2026-07-26 | :white_check_mark: Fixed — carries `e9c238f6fe42` |
| Linux kernel | 7.2.x | 7.2.8 | 7.2 | 2026-08-16 | :white_check_mark: Fixed |
| Linux kernel | 7.1.x | 7.1.13 (EOL) | 7.1.6 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.18.x | 6.18.54 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.12.x | 6.12.111 | 6.12.101 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.6.x | 6.6.157 | 6.6.148 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.1.x | 6.1.188 | 6.1.183 | 2026-08-19 | :white_check_mark: Fixed |
| Linux kernel | 5.15.x | 5.15.221 | 5.15.216 | 2026-08-19 | :white_check_mark: Fixed |
| Linux kernel | 5.10.x | 5.10.270 | 5.10.265 | 2026-08-19 | :white_check_mark: Fixed |
| Debian | sid (unstable) | 7.2.8-1 | 7.1.6-1 | 2026-08-04 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.2.6-1 | 7.1.6-1 | 2026-08-17 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.107-1 | 6.12.101-1 | 2026-08-06 | :white_check_mark: Fixed |
| Debian | 12 (bookworm) | 6.1.187-1 | 6.1.187-1 | 2026-09-08 | :white_check_mark: Fixed |
| Proxmox VE | 9 (default) | 7.0.14-19 | 7.0.14-17 | 2026-09-11 | :white_check_mark: Fixed — via Ubuntu-7.0.0-38.38 |
| NixOS | master | 6.18.54 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | release-26.05 | 6.18.54 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.54 | 6.18.42 | 2026-08-04 | :white_check_mark: Fixed |
| NixOS | Unstable (small) | 6.18.54 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | Unstable (nixpkgs) | 6.18.54 | 6.18.42 | 2026-08-08 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.54 | 6.18.42 | 2026-08-05 | :white_check_mark: Fixed |
| NixOS | 26.05 (small) | 6.18.54 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| Rocky Linux / RHEL | 10 | 6.12.0-211.60.1.el10_2 | 6.12.0-211.60.1.el10_2 | 2026-09-25 | :white_check_mark: Fixed — RHSA-2026:71602 |
| Rocky Linux / RHEL | 9 | 5.14.0-687.52.1.el9_8 | 5.14.0-687.52.1.el9_8 | 2026-09-25 | :white_check_mark: Fixed — RHSA-2026:71700 |
| Rocky Linux / RHEL | 8 | 4.18.0-553.168.1.el8_10 | 4.18.0-553.168.1.el8_10 | 2026-09-24 | :white_check_mark: Fixed — RHSA-2026:71329 |
| Amazon Linux | 2023 (default) | 6.1.186-228.376 | 6.1.186-228.374 | 2026-09-14 | :white_check_mark: Fixed — ALAS2023-2026-2143 |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.103-129.197 | 6.12.103-127.188 | 2026-08-31 | :white_check_mark: Fixed — ALAS2023-2026-2110 |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.48-109.150 | 6.18.44-99.149 | 2026-08-31 | :white_check_mark: Fixed — ALAS2023-2026-2106 |
{.distros}

### Linux kernel

The fix reached mainline in **v7.2-rc5** and has been backported to every
maintained stable line.

**7.1.x is end of life.** Every release from 7.1.6 on carries the fix,
but the line gets no further updates — move to 7.2.x or a long-term line.

To confirm a tree directly, the fix adds a single `ph = pppoe_hdr(skb);`
reload after the `dev_hard_header(skb, dev, ETH_P_PPP_SES, …)` call in
`pppoe_sendmsg()` (`drivers/net/ppp/pppoe.c`); a tree missing that line is
unpatched.

### Debian

**bullseye (Debian 11) left LTS support on 2026-08-31** and no longer
gets security updates. Its last kernel is unpatched — upgrade to bookworm
or trixie.

The `pppoe`, `team`, and `bonding` modules Debian ships autoload on
demand and are not blacklisted by default, so a Debian host with
unprivileged user namespaces enabled exposes the unprivileged local path.

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels, so Debian's status does not
carry over. PVE 9's default `proxmox-kernel-7.0` is built from Ubuntu's
resolute (7.0) kernel sources, and its rebase onto `Ubuntu-7.0.0-38.38`
brought the fix in with that build's upstream stable updates — Proxmox's
own changelog names no PPPoE fix.

- **PVE 8 reached end of life in August 2026**, before any fix reached
  its kernels. Its default `proxmox-kernel-6.8` and its opt-in series
  stay vulnerable, and no fix is coming — upgrade to PVE 9.
- **Superseded series** that PVE 9 still publishes, such as
  `proxmox-kernel-6.17` and `proxmox-kernel-6.14`, ride unpatched Ubuntu
  bases and will not get the fix. A host booting one should move to the
  default `proxmox-kernel-7.0`.

### NixOS

Every NixOS channel and branch in the table defaults to
`linux_6_18` (`linuxPackages`), which carries the fix.
A host that overrides
`boot.kernelPackages` to an older series (`linux_6_1` / `linux_5_15` /
`linux_5_10`) is fixed only if that series is at or past its own
first-fixed release.

Kernel updates land on nixpkgs `master` first and reach each channel
once its Hydra jobset passes, so a channel can sit a few days behind
`master`. The `-small` channels (`nixos-unstable-small`,
`nixos-26.05-small`) run a reduced jobset and pick up kernel updates
fastest.

Which ref a flake input follows:

- `github:NixOS/nixpkgs/nixos-unstable` and
  `github:NixOS/nixpkgs/nixos-26.05` follow those channels — the GitHub
  channel branches are updated to exactly the published channel pins.
- A bare `github:NixOS/nixpkgs` with no ref follows `master`, and
  `github:NixOS/nixpkgs/release-26.05` follows that branch. Both are
  ungated development branches — they carry a kernel bump as soon as it
  lands, often a day or more before a channel publishes it.
- A bare `nixpkgs` registry input resolves by default to
  the `nixpkgs-unstable` channel: a separate channel aimed at
  Nix on other operating systems, not gated on the NixOS tests.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks that carry the vulnerable PPPoE
code; the flaw predates git history, so even EL8's 4.18 kernel is
in-window.

Red Hat advisories beyond the current minor-release kernels in the table:

- **RHEL 10:** 10.0 E2S RHSA-2026:71599.
- **RHEL 9:** 9.6 EUS RHSA-2026:71631; 9.4 E4S RHSA-2026:71569;
  9.2 E4S RHSA-2026:71601 (NFV `kernel-rt` RHSA-2026:71606).
- **RHEL 8:** 8.10 `kernel-rt` RHSA-2026:71330; 8.8 E4S/TUS
  RHSA-2026:71594; 8.6 AUS RHSA-2026:71592; 8.4 AUS RHSA-2026:71565.
- **RHEL 7 ELS:** RHSA-2026:71687 (`kernel-rt` RHSA-2026:71657).
- **RHEL 6 ELS:** RHSA-2026:71649.

On RHEL 9 and 10 the real-time kernel (`kernel-rt`) is fixed by the
same advisories as the regular kernel; RHEL 9.2 E4S, 8 and 7 have
separate `kernel-rt` advisories, listed with the kernel's.

AlmaLinux, CloudLinux and Oracle Linux's Red Hat Compatible Kernel
rebuild RHEL's kernel, so they get the fix as they rebuild Red Hat's
advisories.

### Amazon Linux

The three AL2023 streams are the default `kernel` package (6.1 line) and
the opt-in `kernel6.12` and `kernel6.18` packages. Amazon builds carry
their own cherry-picks, so a stream can be fixed at a build below its
line's upstream first-fixed release — judge an AL2023 kernel by its
ALAS, not its version number.

Amazon Linux 2 reached end of support on 2026-06-30 and gets no fix —
migrate to AL2023.

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
- **Every tracked distribution ships a fix; unrebooted hosts remain
  exposed.** The fix reaches every maintained upstream stable line, and
  Debian, Proxmox VE 9, all tracked NixOS refs, Amazon Linux 2023, and the
  whole Rocky Linux / RHEL family (8, 9, and 10) have adopted it. Check the
  running kernel against the *First fixed* column, not the kernel's age.
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
- **CVE-2026-68121** (via `vulns.git` `origin/master`,
  `cve/published/2026/CVE-2026-68121.{json,dyad,cvss}`):
  - Assigned by the kernel CNA, published 2026-08-10.
  - The record keys on `e9c238f6fe42fb1b4dba3a578277de32cb487937`.
  - The `.dyad` lists a vulnerable:fixed pair for every maintained line:
    `2.6.12 → 5.10.265`, `→ 5.15.216`, `→ 6.1.183`, `→ 6.6.148`,
    `→ 6.12.101`, `→ 6.18.42`, `→ 7.1.6`, and `→ 7.2`.
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

- **Kernel CNA** (`vulns.git` `.cvss`/`.json`, `origin/master`):
  - CVSS 3.1 **7.8 HIGH**
    (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`).
  - `AV:L` because the trigger is the local `sendmsg()` syscall on a
    PF_PPPOX socket, not remote reception.
  - `PR:L` because a PPPoE socket needs no privilege and the team/GRE
    topology is reachable with `CAP_NET_ADMIN` in an unprivileged user
    namespace.
- **Red Hat** (CSAF/VEX, initial release 2026-08-10, current revision 3 /
  2026-09-25): CVSS 3.1 **7.3 HIGH** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H`),
  impact **Important** — the same local vantage, scoring integrity `I:L`
  rather than the CNA's `I:H`. Per-stream remediation status is in
  *Distributions* below.
- **NVD / EPSS / KEV**: NVD record status *Received* (its CVSS 3.1 mirrors
  the CNA score rather than an independent assessment); no CWE assigned.
  EPSS **~0.30%** (~20th percentile, via api.first.org); not in CISA KEV.

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
  Proxmox base):
  - `resolute` *pending* (`7.0.0-38.38` named, not yet released).
  - `noble` *needed*.
  - `jammy` *pending* (`5.15.0-198.208`).
  - `focal` *needed*; `bionic`/`xenial`/`trusty` *needed*.
  - The feed's "upstream: released" entry cites `7.2~rc5`, `6.8.y`,
    `6.17.y`, and `7.0.y`; a direct `pppoe.c` read (above) shows the three
    frozen branches do not carry the fix, so this is not read as a
    Proxmox fix path.
- **Proxmox VE** (`~/src/proxmox/pve-kernel`; pve-no-subscription
  `Packages.gz`, which also gives the *Current kernel* build):
  - The default series is `proxmox-kernel-7.0` (PVE 9, trixie).
  - PVE 9's `7.0.14-17` rebased onto `Ubuntu-7.0.0-38.38`
    (`origin/master` changelog); its `submodules/ubuntu-kernel` pin
    `740b32353f43` is exactly that tag's commit (`git ls-remote` of
    Proxmox's `mirror_ubuntu-kernels`).
  - Builds before `7.0.14-17` sit on `Ubuntu-7.0.0-31.31` or older, with
    no later Ubuntu rebase and no PPPoE cherry-pick.
  - PVE 9's `debian/changelog` names no PPPoE cherry-pick of its own;
    the fix arrives only through the Ubuntu base.
  - Ubuntu's packaging changelog for `7.0.0-38.38`
    (changelogs.ubuntu.com) carries the fix: it lists `CVE-2026-68121`
    with the `pppoe: reload header pointer after dev_hard_header()`
    subject (stable patchset 2026-08-26, LP: #2165189).
  - Ubuntu's *pending* status for resolute concerns its own archive, not
    the source Proxmox builds from, so it does not hold the PVE row back.
  - `7.0.14-18` rebased onto a later resolute base (upstream stable
    7.1.8–7.1.13), and `7.0.14-19` keeps that base.
  - *Fixed since* is the `Last-Modified` of the `7.0.14-17` `.deb` in
    `pve-no-subscription`.
  - PVE 8 reached end of life in 2026-08 (Proxmox VE FAQ lifecycle
    table, pve.proxmox.com/wiki/FAQ), before this tracker existed.
  - `origin/bookworm-6.8`'s changelog named no PPPoE cherry-pick and
    its `patches/kernel/` held no `pppoe` patch at the final build.
  - Ubuntu marks the 6.8 (noble) kernel *needed*.
- **NixOS** (via `~/src/nixos/nixpkgs`; branch refs from the clone,
  channels via their `git-revision` pins):
  - `packageAliases.linux_default = linux_6_18` at every tracked ref.
  - Each row's *Current kernel* is the `6.18` version `kernels-org.json`
    resolves at that ref.
  - `master` bumped to the fixed **6.18.42** on 2026-08-03 in
    `b658e06342e8` (`git log -S` on `kernels-org.json`).
  - `release-26.05` bumped to **6.18.42** on 2026-08-03 in
    `33565191d37a`.
  - Channel *Fixed since* via
    `scripts/nixos-first-shipped <channel> <bump-commit>`, from the master
    bump: `nixos-unstable` 2026-08-04, `nixos-unstable-small` 2026-08-03,
    `nixpkgs-unstable` 2026-08-08.
  - From the release-26.05 bump: `nixos-26.05` 2026-08-05,
    `nixos-26.05-small` 2026-08-03.
- **Rocky / RHEL family** (Red Hat CSAF/VEX,
  `security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-68121.json`,
  current revision 3 / 2026-09-25):
  - RHEL 10.2 — the current stream Rocky 10 tracks — is fixed by
    RHSA-2026:71602 (`6.12.0-211.60.1.el10_2`), covering
    AppStream/BaseOS/CRB/NFV/RT.
  - RHEL 10.0 (E2S) is fixed by RHSA-2026:71599
    (`6.12.0-55.107.1.el10_0`).
  - RHEL 9.8 (MAIN EUS) — the current stream Rocky 9 tracks — is fixed
    by RHSA-2026:71700 (`5.14.0-687.52.1.el9_8`).
  - RHEL 9.6 (EUS) is fixed by RHSA-2026:71631 (`5.14.0-570.144.1.el9_6`)
    — a legacy extended-support stream, not the current release Rocky 9
    tracks.
  - RHEL 9.4 (E4S) is fixed by RHSA-2026:71569 — likewise a legacy
    extended-support stream.
  - RHEL 9.2 (E4S) is fixed by RHSA-2026:71601
    (`5.14.0-284.194.1.el9_2`); its NFV `kernel-rt` (E4S) is fixed by
    RHSA-2026:71606 (`5.14.0-284.194.1.rt14.479.el9_2`).
  - RHEL 8.10 (MAIN EUS) `kernel` is fixed by RHSA-2026:71329
    (`4.18.0-553.168.1.el8_10`).
  - RHEL 8.10 `kernel-rt` is fixed by RHSA-2026:71330
    (`4.18.0-553.168.1.rt7.509.el8_10`), superseding the earlier
    "Will not fix" determination.
  - RHEL 8.8 (E4S/TUS) is fixed by RHSA-2026:71594.
  - RHEL 8.6 (AUS) is fixed by RHSA-2026:71592.
  - RHEL 8.4 (AUS) is fixed by RHSA-2026:71565.
  - RHEL 7 ELS is fixed by RHSA-2026:71687 and RHEL 7 RT-ELS by
    RHSA-2026:71657; EL7 is EOL and untracked here.
  - RHEL 6 ELS is fixed by RHSA-2026:71649; EL6 is EOL and untracked
    here.
  - The record lists RHEL 9 `kernel-rt` as `known_affected`, but
    RHSA-2026:71700 (9.8), RHSA-2026:71631 (9.6) and RHSA-2026:71569
    (9.4) also cover the RHEL 9 RT and NFV products.
  - OSV's `related` field lists only `ALSA-2026:71329` and
    `ALSA-2026:71330` — AlmaLinux has rebuilt the RHEL 8.10 fix but not
    the RHEL 9.8 or RHEL 10.2 fix.
  - Rocky's *Current kernel* NVRs are read from BaseOS repodata
    (`primary.xml.gz`, highest `rel` via `rpmsort`).
  - Rocky 10 shipped `6.12.0-211.60.1.el10_2`, the NVR
    named by RHSA-2026:71602; an `other.xml.gz` changelog query confirms
    the `CVE-2026-68121` entry (author `... [6.12.0-211.60.1.el10_2]`),
    uploaded 2026-09-25 per the `Packages/k/` directory listing.
  - Rocky 9 shipped `5.14.0-687.52.1.el9_8`, the NVR named
    by RHSA-2026:71700; the same query confirms the `CVE-2026-68121`
    entry (author `... [5.14.0-687.52.1.el9_8]`), uploaded 2026-09-25 per
    the `Packages/k/` directory listing.
  - Rocky 8 shipped `4.18.0-553.168.1.el8_10`, the NVR
    named by RHSA-2026:71329; the same query confirms the
    `CVE-2026-68121` entry (author `... [4.18.0-553.168.1.el8_10]`),
    uploaded 2026-09-24 per the `Packages/k/` directory listing.
- **Amazon Linux** (AL2023 `x86_64` mirror: `updateinfo.xml.gz` via
  `scripts/alas-cve`; per-stream *Current kernel* from `primary.xml.gz`,
  highest `ver`/`rel`):
  - **ALAS2023-2026-2143** (Important, 2026-09-14) fixes the default
    `kernel` stream at `6.1.186-228.374.amzn2023`.
  - **ALAS2023-2026-2110** (Important, 2026-08-31) fixes `kernel6.12` at
    `6.12.103-127.188.amzn2023`.
  - **ALAS2023-2026-2106** (Important, 2026-08-31) fixes `kernel6.18` at
    `6.18.44-99.149.amzn2023`.
  - AL2 is EOL (2026-06-30).
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
