# ADR 0001: FFmpeg Distribution Profile

- Date: 2026-09-26
- Status: Blocked pending owner/legal review, native artifact evidence, and a replacement Windows candidate

## Context

FluxForm invokes FFmpeg as a separate executable. That process boundary does not settle the licensing analysis. Redistribution obligations and patent exposure require product-owner and legal approval before any public release.

The cached Windows file at `tools-cache/ffmpeg-release-essentials.zip` measures 109,982,658 bytes with SHA-256 `47b1cc6e4ff1a8b1a661799f22e70bfb48ba16b3dffa04ff0871683ea5d20d73`. A prior report recorded its bundled README as identifying `8.1.1-essentials_build-www.gyan.dev`, GPL v3, FFmpeg source commit `239f2c733d`, and network support. It also recorded `ffmpeg.exe` as 101,457,920 bytes / SHA-256 `228d7a8556258de907fdb55f36850078ebc7680b84ec30d84ea02e99bec1d1eb`, `ffprobe.exe` as 101,251,072 bytes / SHA-256 `0fde260f5abd35c9cafd96f594cc76365a780c1b73a90e35b6a3409ea1db1bf0`, and the bundled `LICENSE` as 35,147 bytes / SHA-256 `8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903`. Those executable/license values are historical declarations, not evidence accepted by the checked-in verifier.

Review round 1's read-only structural inspection found two EOCD records. The first is at byte 109,282,220 and its declared central directory (offset 109,275,818; size 6,402) ends there. Another 700,416 bytes follow, ending in a duplicate EOCD at byte 109,982,636 that points back to the earlier central directory. The checked-in verifier rejects these inconsistent terminal bounds before creating an extraction directory or launching FFmpeg. The trusted system extractor, `C:\Windows\System32\tar.exe` (bsdtar 3.8.8), independently reports `Damaged Zip archive` for this file. The cached archive was not extracted, and its FFmpeg/FFprobe binaries were not run, in review round 1; extraction tests used only synthetic safe ZIP fixtures. The earlier JSON at `target/stage0/ffmpeg-windows-x86_64.json` predates this review and is stale; it is not accepted as gate evidence.

## Decision

Keep the cached Windows row marked `candidate` only to preserve the rejected input's immutable identity in `config/ffmpeg-profile.toml`; operationally, this archive is rejected as structurally inconsistent and is not a usable technical candidate. Replace it with a clean archive and regenerate evidence through the checked-in archive verifier before accepting any Windows result. The stale report and historical executable/license declarations do not validate the current archive. The distribution gate remains `blocked`.

The product-owner approval has not been supplied or recorded. No legal approval is recorded. This ADR therefore makes no release or licensing approval decision. A dated ADR decision recording product-owner approval, together with legal review, is required before the distribution gate can be marked approved.

The prior report recorded network support, which must be re-established from a clean replacement candidate. Any accepted future invocation must constrain FFmpeg protocols to the profile allowlist (`file`, `pipe`), and a server deployment must also enforce its OS-level network sandbox. The invocation allowlist and OS sandbox are separate controls; neither removes the need for owner/legal review.

## Required evidence before the distribution gate can turn green

Provide native artifacts for Windows x86_64, macOS x86_64, macOS aarch64, and Linux x86_64. Every row must bind an immutable URL or internal artifact identity, SHA-256, license text, source correspondence, target triple, and an equivalent required capability set. Each report must be collected natively for its target; translated or emulated output does not replace native evidence.

The distribution gate remains red until all required platform rows are approved and their evidence is reviewed. This ADR records only the rejected Windows cache input; it does not claim current Windows verification or macOS/Linux evidence.
