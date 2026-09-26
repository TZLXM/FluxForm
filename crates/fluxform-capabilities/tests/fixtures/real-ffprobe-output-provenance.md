# TEST-ONLY FFprobe output fixtures

`real-ffprobe-inputs-v1.json`, `real-ffprobe-mp4-output.json`, and
`real-ffprobe-m4a-output.json` contain the fields consumed by the runner,
captured from actual FFprobe JSON output after
converting the checked-in CC0 synthetic MOV and M4A samples with local FFmpeg
5.1.1-full_build-www.gyan.dev (generator SHA-256
`ff3360e9733af335b94518dafa86984df17c3b06da9e4e877d94306a21ac880`). Both
conversions used `-map_metadata -1`; the video diagnostic used FFmpeg's
explicit `-autorotate 1` input option. Output observations still contain MP4
structural tags (`major_brand`, `minor_version`, `compatible_brands`,
`handler_name`, `vendor_id`) and generated `encoder` tags. The test ensures the
normalizer excludes structural fields while retaining user metadata.

These are regression fixtures only. They are not approved FFmpeg artifacts,
distribution/legal records, or native platform reports.
