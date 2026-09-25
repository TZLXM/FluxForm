# ADR 0001: FFmpeg Distribution Profile

- Date: 2026-09-26
- Status: Blocked pending owner/legal review and native artifact evidence

## Context

FluxForm invokes FFmpeg as a separate executable. That process boundary does not settle the licensing analysis. Redistribution obligations and patent exposure require product-owner and legal approval before any public release.

The cached Windows archive at `tools-cache/ffmpeg-release-essentials.zip` was inspected without changing it. Its bundled README identifies the build as `8.1.1-essentials_build-www.gyan.dev`, declares GPL v3, and points to FFmpeg source commit `239f2c733d` at `https://github.com/FFmpeg/FFmpeg/commit/239f2c733d`. The README reports network support. The archive is 109,982,658 bytes with SHA-256 `47b1cc6e4ff1a8b1a661799f22e70bfb48ba16b3dffa04ff0871683ea5d20d73`.

The archive's Windows x86_64 executables were extracted to a unique temporary directory for inspection and verification, then removed. `ffmpeg.exe` is 101,457,920 bytes with SHA-256 `228d7a8556258de907fdb55f36850078ebc7680b84ec30d84ea02e99bec1d1eb`. `ffprobe.exe` is 101,251,072 bytes with SHA-256 `0fde260f5abd35c9cafd96f594cc76365a780c1b73a90e35b6a3409ea1db1bf0`. The bundled `LICENSE` is 35,147 bytes with SHA-256 `8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903`.

## Decision

Record the cached Windows x86_64 archive as a technical candidate in `config/ffmpeg-profile.toml`, identified by its internal cache path and archive SHA-256. It is not an approved distribution artifact. The verification report confirms matching FFmpeg/FFprobe versions and configuration and the required MP4/MOV, AAC/H.264, and `file`/`pipe` capabilities. The report marks the artifact `candidate`; its approval record fields are empty, and the distribution gate remains `blocked`.

The product-owner approval has not been supplied or recorded. No legal approval is recorded. This ADR therefore makes no release or licensing approval decision. A dated ADR decision recording product-owner approval, together with legal review, is required before the distribution gate can be marked approved.

The verified build has network support. Any future invocation must constrain FFmpeg protocols to the profile allowlist (`file`, `pipe`), and a server deployment must also enforce its OS-level network sandbox. The invocation allowlist and OS sandbox are separate controls; neither removes the need for owner/legal review.

## Required evidence before the distribution gate can turn green

Provide native artifacts for Windows x86_64, macOS x86_64, macOS aarch64, and Linux x86_64. Every row must bind an immutable URL or internal artifact identity, SHA-256, license text, source correspondence, target triple, and an equivalent required capability set. Each report must be collected natively for its target; translated or emulated output does not replace native evidence.

The distribution gate remains red until all required platform rows are approved and their evidence is reviewed. This ADR records only the Windows candidate; it does not claim macOS or Linux evidence.
