# Third-party notices

The code in this repository is MIT-licensed (`LICENSE`, Copyright (c) 2026 Tirion) unless this file says otherwise.

## Bundled third-party code and data

None. The fixture sets in `tests/fixtures/` (messages, DKIM keys, DNS zones and recorded verdicts) are synthetic,
generated for this repository; every domain in them is under `.test`.

## Dependencies (not bundled)

NuGet packages, pinned with content hashes in `packages.lock.json` and restored at build time; nothing from them is
redistributed in this repository:

- [MimeKit](https://github.com/jstedfast/MimeKit) (`MimeKit.Cryptography`, MIT).
- Tests: [xUnit.net](https://xunit.net/) v3 (Apache-2.0). Fuzzing: [SharpFuzz](https://github.com/Metalnem/sharpfuzz) (MIT).
