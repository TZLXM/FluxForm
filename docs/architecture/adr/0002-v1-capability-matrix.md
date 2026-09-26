# ADR 0002: Freeze the v1 capability matrix

Status: **Approved for product scope; technical/distribution evidence gate remains blocked**

**Decision date:** 2026-09-26

## Context

Section 6 of the platform design names candidate input and output families, but a container name alone does not promise every codec or stream topology inside it. The Task 3 FFmpeg profile is not approved for distribution and native reports for the four target profiles are absent. Task 5 therefore needs an explicit product-scope decision before it can create the manifest and sample corpus.

## Decision

On 2026-09-26 the product owner approved the exact 129-row `{edge_id,status}` matrix below with the exact response **“批准”**. It contains three `enabled` rows and 126 `deferred` rows. This approval covers the v1 product-scope matrix only. It does **not** approve FFmpeg redistribution or GPL/patent/legal posture, any FFmpeg artifact, or native technical evidence on Windows, macOS, or Linux.

Only these narrow flows are enabled: H.264-only, single-video-stream MOV to H.264/MP4; AAC-only single-audio-stream M4A to M4A; and one-frame JPEG to PNG. The image edge still requires per-target image capability confirmation before the manifest can pass technical validation. Each enabled edge binds all four target profile IDs and names planned valid and invalid sample IDs in the machine-readable block. Those identifiers do not imply sample reports exist.

Every other listed directed pair remains deferred. Deferred rows carry their reason, accountable owner, and reconsideration condition in the approval record below. Same-format pairs are defined as explicit re-encode/normalization operations rather than byte-copy no-ops. JPEG/JPG, TIFF/TIF, and HEIC/HEIF are normalized to one family each; MPG and MPEG remain separate because section 6 lists them separately. Animated GIF, animated WebP, and multi-page TIFF are invalid sample cases only and are not edges.

## Consequences and limits

- The manifest may contain only the three enabled edges; the public capability response is derived from that manifest alone.
- The local Windows profile report remains `blocked`/`candidate`, has no approval record/date, and cannot validate or authorize an edge. Approved artifact rows and four native profile/sample reports must be supplied before the technical gate can pass.
- Missing or stale evidence is `BLOCKED`; no synthetic test fixture or profile feature list substitutes for a native sample report.
- The separate owner/legal distribution gate remains required.

## Machine-readable approved matrix

The JSON array below is the complete, normalized approval record. `enabled` rows include the four intended target IDs and planned sample IDs; `deferred` rows include reason, owner, and reconsideration.

<!-- matrix-json-v1:begin -->
```json
[
  {
    "edge_id": "video.mp4-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mp4-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mp4-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mp4-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mov-to-mp4",
    "status": "enabled",
    "target_profiles": [
      "windows-x86_64",
      "macos-aarch64",
      "macos-x86_64",
      "linux-x86_64"
    ],
    "valid_samples": [
      "video-mov-h264-silent-240p-v1"
    ],
    "invalid_samples": [
      "video-mov-hevc-silent-unsupported-v1"
    ]
  },
  {
    "edge_id": "video.mov-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mov-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mov-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mkv-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mkv-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mkv-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mkv-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.webm-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.webm-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.webm-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.webm-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.avi-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.avi-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.avi-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.avi-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.m4v-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.m4v-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.m4v-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.m4v-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mpg-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mpg-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mpg-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mpg-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mpeg-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mpeg-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mpeg-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.mpeg-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.wmv-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.wmv-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.wmv-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.wmv-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.flv-to-mp4",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.flv-to-mov",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.flv-to-mkv",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "video.flv-to-webm",
    "status": "deferred",
    "reason": "The exact input decoder/demuxer and output muxer/codec combination is outside the narrow MOV/H.264 to MP4/H.264 recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.mp3-to-mp3",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.mp3-to-aac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.mp3-to-m4a",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.mp3-to-wav",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.mp3-to-flac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.mp3-to-ogg",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.mp3-to-opus",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.aac-to-mp3",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.aac-to-aac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.aac-to-m4a",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.aac-to-wav",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.aac-to-flac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.aac-to-ogg",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.aac-to-opus",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.m4a-to-mp3",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.m4a-to-aac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.m4a-to-m4a",
    "status": "enabled",
    "target_profiles": [
      "windows-x86_64",
      "macos-aarch64",
      "macos-x86_64",
      "linux-x86_64"
    ],
    "valid_samples": [
      "audio-m4a-aac-lc-mono-v1"
    ],
    "invalid_samples": [
      "audio-m4a-alac-unsupported-v1"
    ]
  },
  {
    "edge_id": "audio.m4a-to-wav",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.m4a-to-flac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.m4a-to-ogg",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.m4a-to-opus",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wav-to-mp3",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wav-to-aac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wav-to-m4a",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wav-to-wav",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wav-to-flac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wav-to-ogg",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wav-to-opus",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.flac-to-mp3",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.flac-to-aac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.flac-to-m4a",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.flac-to-wav",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.flac-to-flac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.flac-to-ogg",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.flac-to-opus",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.ogg-to-mp3",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.ogg-to-aac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.ogg-to-m4a",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.ogg-to-wav",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.ogg-to-flac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.ogg-to-ogg",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.ogg-to-opus",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.opus-to-mp3",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.opus-to-aac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.opus-to-m4a",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.opus-to-wav",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.opus-to-flac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.opus-to-ogg",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.opus-to-opus",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wma-to-mp3",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wma-to-aac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wma-to-m4a",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wma-to-wav",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wma-to-flac",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wma-to-ogg",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "audio.wma-to-opus",
    "status": "deferred",
    "reason": "The exact source codec or output codec/container is outside the narrow AAC/M4A recommendation or is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after approved artifacts and native reports exist for all four target profile IDs, and exact codec/container mapping plus real valid/invalid samples for this edge pass on every target."
  },
  {
    "edge_id": "image.jpeg-to-jpeg",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.jpeg-to-png",
    "status": "enabled",
    "target_profiles": [
      "windows-x86_64",
      "macos-aarch64",
      "macos-x86_64",
      "linux-x86_64"
    ],
    "valid_samples": [
      "image-jpeg-baseline-rgb-v1"
    ],
    "invalid_samples": [
      "image-jpeg-truncated-v1",
      "image-gif-animated-v1",
      "image-webp-animated-v1",
      "image-tiff-multipage-v1"
    ]
  },
  {
    "edge_id": "image.jpeg-to-webp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.jpeg-to-bmp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.jpeg-to-tiff",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.png-to-jpeg",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.png-to-png",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.png-to-webp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.png-to-bmp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.png-to-tiff",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.webp-to-jpeg",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.webp-to-png",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.webp-to-webp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.webp-to-bmp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.webp-to-tiff",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.bmp-to-jpeg",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.bmp-to-png",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.bmp-to-webp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.bmp-to-bmp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.bmp-to-tiff",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.tiff-to-jpeg",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.tiff-to-png",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.tiff-to-webp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.tiff-to-bmp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.tiff-to-tiff",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.gif-to-jpeg",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.gif-to-png",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.gif-to-webp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.gif-to-bmp",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.gif-to-tiff",
    "status": "deferred",
    "reason": "The exact image decoder/encoder, muxer, alpha/orientation/metadata policy, or single-frame behavior is not evidenced on every target.",
    "owner": "Media/Core",
    "reconsideration": "Reconsider after the four approved target profiles explicitly include required image capabilities and native sample reports verify this edge's frame, alpha, orientation, metadata, and failure policies."
  },
  {
    "edge_id": "image.heic-to-jpeg",
    "status": "deferred",
    "reason": "The design explicitly reserves HEIC/HEIF as a later compatibility-input path, potentially through a separate libheif backend.",
    "owner": "Product + Media/Core",
    "reconsideration": "Reconsider in a later scope decision after the separate HEIC/HEIF backend, redistribution/license posture, and four-target sample evidence are defined."
  },
  {
    "edge_id": "image.heic-to-png",
    "status": "deferred",
    "reason": "The design explicitly reserves HEIC/HEIF as a later compatibility-input path, potentially through a separate libheif backend.",
    "owner": "Product + Media/Core",
    "reconsideration": "Reconsider in a later scope decision after the separate HEIC/HEIF backend, redistribution/license posture, and four-target sample evidence are defined."
  },
  {
    "edge_id": "image.heic-to-webp",
    "status": "deferred",
    "reason": "The design explicitly reserves HEIC/HEIF as a later compatibility-input path, potentially through a separate libheif backend.",
    "owner": "Product + Media/Core",
    "reconsideration": "Reconsider in a later scope decision after the separate HEIC/HEIF backend, redistribution/license posture, and four-target sample evidence are defined."
  }
]
```
<!-- matrix-json-v1:end -->
