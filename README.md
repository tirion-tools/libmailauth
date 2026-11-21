# libmailauth

Mail authentication for a receiving mail client in .NET: one verdict per message (verified, verified-forwarded,
unaligned, failed or none, with temporary and pending states) from DKIM, ARC and DMARC, the account's own server's
`Authentication-Results`, and its spam-filter verdict headers. Assembly and namespace `MailAuth`, .NET 10,
NativeAOT-compatible, no network access of its own.

## Builds on

libmailauth builds on [MimeKit](https://github.com/jstedfast/MimeKit) 5 (`MimeKit.Cryptography` 5.0.0, MIT): its
`DkimVerifier`, `ArcVerifier` and `DmarcVerifier` do all signature checking, ARC chain validation, DMARC policy
discovery, identifier alignment and the Organizational Domain, and every DNS lookup goes through MimeKit's
`IDnsResolver`. It does not replace them. Bugs and missing features in those verifiers are fixed upstream in MimeKit,
and in [BouncyCastle](https://github.com/bcgit/bc-csharp) for key handling.

**The one exception is header-only DKIM** (`b=` checked from the header block, before the body is downloaded):
MimeKit verifies the body hash before the header signature and has no way to skip it, so `HeaderOnlyVerifier` has its
own RFC 6376 header canonicalization, `h=` selection and RSA-SHA256 / Ed25519-SHA256 check on BouncyCastle; DMARC for
it is still MimeKit's `DmarcVerifier`.

What MimeKit does not offer, and the library works around today, is drafted for upstream (not filed yet; each is
removed here once released upstream):

| Draft | Ask | Workaround here |
|---|---|---|
| MimeKit 1: DKIM body length | an `l=` policy, or the canonical body length on the result | `AuthEvaluator.CanonicalBodyLength` turns a pass whose `l=` does not cover the body into a fail |
| MimeKit 2: header-only DKIM | `DkimVerifier` checking `b=` with the body hash skipped | `HeaderOnlyVerifier` |
| MimeKit 3: Organizational Domain API | a public `GetOrganizationalDomain` | `AuthEvaluator.OrgDomain` runs `DmarcVerifier` on a probe message |
| MimeKit 4: DKIM key status | missing / revoked / present key state on the result | `BrokeredDnsResolver.KeyState` reads the cached raw answer |
| MimeKit 5: ARC instance data | sealer domain and AAR per instance on `ArcValidationResult` | `AuthEvaluator` re-parses ARC-Seal `i=`/`d=` with `Tags` |
| MimeKit 6: DKIM key cache | a validated-key cache instead of rebuilding the key per signature | `KeyValidation` (below) |
| bc-csharp 6: RSA modulus validation cache | validate each modulus once (`m_validated`) | `KeyValidation`: each key record validated once with the full default checks, then MimeKit runs under a thread-scoped `RsaMaxMRTests=0` |

What it adds is the receiving client's policy layer, which MimeKit leaves to the application:

- which `Authentication-Results` or provider-sealed `ARC-Authentication-Results` to trust for an account (authserv-id
  match, topmost header, highest sealed instance in a passing chain);
- one combined verdict with temporary and pending states;
- a trusted-forwarder rule that requires the sealer's own DKIM signature, with a curated sealer-to-signer list
  (`Data/sealer-signers.json`);
- stricter local rules: `l=` must cover the body, RSA under 1,024 bits and rsa-sha1 do not count, at most 5
  signatures, two From headers fail, DNS errors from another organization cannot turn a failure into a temporary
  result;
- header-only DKIM for messages whose body is not downloaded yet;
- flags for the caller's history rules (no signature from a domain that usually signs, every key gone);
- binding of SpamAssassin, amavis, rspamd and Exchange Online verdict headers to the receiving server by
  Authentication-Results position and queue id, and bounded grammars for those fields;
- an `IDnsResolver` over a caller-supplied TXT transport, with bounded answers, a persisted cache and no network
  access of its own.

Related projects: [DKIM Verifier](https://github.com/lieser/dkim_verifier) (Thunderbird add-on; reads
Authentication-Results by trusted authserv-id, defaulting to the newest header, where this library takes the topmost
matching one), [mailauth](https://github.com/postalsys/mailauth) (Node.js; server-side SPF/DKIM/DMARC/ARC and
sealing), [mail-auth](https://github.com/stalwartlabs/mail-auth) (Rust; server-side DKIM/ARC/SPF/DMARC). None of
them is a .NET library or covers the client-side trust boundary or provider verdicts.

## Scope

In scope: the verdict of a received message for one account, header-only and full; provider verdict binding; the TXT
resolver and its cache rules.

Not in scope:
- SPF (a client sees the message long after the SMTP transaction; MimeKit's `DmarcVerifier` gets no SPF result);
- signing, sealing and anything server-side;
- the DNS transport itself, persistence of the cache and of signing history, settings, UI and how a verdict is shown:
  all the caller's;
- reading spam and phishing flags out of the bound verdict fields: the library binds the fields and parses their
  grammars, the caller decides what a score or a rule name means.

## API

```csharp
using MailAuth;
using MimeKit;

// One per thread: the resolver caches answers, the evaluator caches organizational domains.
var dns = new BrokeredDnsResolver(persistedRows, transport, row => Persist(row));   // ITxtTransport, TxtCacheRow
var evaluator = new AuthEvaluator(dns, registrableDomain);                          // Func<string, string?> (PSL eTLD+1)

var policy = new AuthPolicy(
    AuthservId: "mx.example.net",           // the account's receiving server, exact or "*.suffix"; null: local only
    ProviderSealers: [],                    // the provider's ARC sealers when it seals instead of stamping
    ForwarderSealers: [],                   // sealers the user trusts as forwarders
    SealerSigners: SealerSigners.Shipped,   // sealer org domain -> accepted DKIM signers
    Verdicts: VerdictConfig.ForStampingServer("mx.example.net"));   // or null: read no provider verdicts

dns.Token = cancellationToken;              // MimeKit's synchronous verifiers pass no token
AuthOutcome o = evaluator.Evaluate(message, rawMessage, policy);                    // whole message
AuthOutcome h = evaluator.EvaluateHeaderOnly(message, headerBlock, rfc822Size, policy);   // header block only
// o.Source: provider_sealed | trusted_arh | local | none
// o.Verdict: verified | verified_forwarded | unaligned | failed | none; o.Temporary; o.PendingOpen
// o.VerifiedDomain, o.ViaDomain, o.Policy, o.Dkim (DkimInfo per signature), o.Ignored, o.Reason
// o.UnsignedDmarcFail, o.KeyGone, o.SigningEvidence: inputs of the caller's history rules
// o.SealedAar: the provider-sealed results the verdict came from

var fields = ProviderVerdicts.FromHeaders(message.Headers);   // null over MaxHeaderFields
var bound = ProviderVerdicts.Bind(fields!, policy.Verdicts!);  // Fields (name -> field, form), Anchor, Ignored
var status = ProviderVerdicts.ParseSpamStatus(value);          // also ParseSpamdResult, ParsePairs, Centi
```

- **Strings, not enums,** for `Source`, `Verdict`, `Policy` and `DkimInfo.Result`: they are the values of the
  Authentication-Results registry and of the verdict model above, and callers store them.
- **History rules are the caller's.** `UnsignedDmarcFail` (no signature, local DMARC fail) and `KeyGone` (DMARC fail,
  every key missing or revoked) mark a `failed` verdict the caller may soften: for example to `none` when the From
  organization has no signing history before the message, or when the message was old at its first sync.
  `SigningEvidence` marks a message that is evidence of signing for the From organization.
- **`ITxtTransport.Ask`** answers a TXT name with `Ok`, `NoData`, `NxDomain`, `Temp` or `Refused`, synchronously.
  The resolver asks only `<selector>._domainkey.<domain>` and `_dmarc.<domain>` names, never a special-use top label;
  any other name is answered non-existent locally. Final answers go to the persist callback as `TxtCacheRow` (status
  `ok|nodata|nxdomain`, records as a JSON array) and come back through the constructor; temporary answers are held
  30 s in memory and never persisted.
- **`Tags.Parse`** is the RFC 6376 tag-list parser the library uses for DKIM, ARC and DMARC records.

## Security model

- **Input is hostile:** the message, every header, and every TXT answer. Every parser is bounded: at most 1,000 header
  fields and 8 KiB per verdict field, 256 tests, 64 pairs, 64 tags; TXT answers at most 16 records, 2,048 bytes each,
  4,096 in total, printable ASCII only, names at most 253 bytes. A reply outside those limits is a temporary
  failure, a persisted row outside them is dropped and asked again. Nothing is guessed: a field outside its grammar
  is unparsable and not read.
- **Trust boundary.** An `Authentication-Results` header is trusted only when it is the topmost one and its
  authserv-id matches the account; every other one is counted and ignored. For a provider that seals, only the
  highest instance it sealed in a chain that validates counts, and its plain `Authentication-Results` never do.
  Provider verdict fields count only in the form the server writes them: above its own stamp (prepended), bottom-most
  in one block with a queue-id field equal to the queue id of the server's own `Received` (appended), or exactly once
  (firewalled). A sender can write none of these positions.
- **Failing closed, never failing open:** DNS trouble yields `none` with `Temporary`, never `failed` and never
  `verified`; a broken key server of another organization cannot turn a failure into a temporary result; a
  signature that does not count (`l=` short of the body, weak key, rsa-sha1) can only lower a verdict.
- **RSA key validation.** Each key record is validated once with BouncyCastle's full default checks (a prime modulus
  is rejected) before MimeKit sees it; only then, on the calling thread and only around MimeKit's verifier calls,
  is the per-signature re-validation skipped. A process-wide skip is never used.
- **No I/O, no reflection.** The library makes no system calls of its own (DNS goes through the caller's transport),
  uses source-generated JSON and generated regular expressions, and is checked by the trim and AOT analyzers
  (`IsAotCompatible`). It is not thread-safe: use one evaluator and resolver per thread.
- **Dependencies** are pinned with content hashes in `packages.lock.json` and restored in locked mode; the audit job
  checks them against the NuGet vulnerability data.

## Tests

- `tests/fixtures/` holds three synthetic fixture sets (`dkim-aot`, `arc-sealer-dkim`, `provider-verdicts`): signed
  messages, each with its own keys, its DNS zone (`zone.json`) and the recorded verdicts per account configuration
  (`expected.json`). All domains are under `.test`.
- `EvaluatorTests`: every fixture under every configuration against the recorded verdicts (56 x 3, 106 x 3, 106 x 3),
  header-only verdicts (106 + 106), provider-verdict binding (anchor and binding counts), forged and misplaced
  Authentication-Results, two From headers, `l=`, a prime-modulus key, an attacker-sealed ARC chain, SERVFAIL on the
  key, key-gone and signing-evidence flags, a bad selector, mutated messages, and the cache rules across a restart.
- `ParserTests`: the resolver's reply mapping, name policy, persisted rows and key state; the tag-list parser; the
  header-only field split and canonicalization; the verdict grammars; the shipped sealer-signer list.
- `fuzz/` is a SharpFuzz harness with three targets: `tags` (the tag-list parser), `headeronly` (the header-only
  field split and canonicalization) and `verdicts` (`ParseSpamStatus`, `ParseSpamdResult`, `ParsePairs`).

## Gates

Every check runs locally, in a pinned toolchain container (`tools/container/Dockerfile`: the .NET 10 SDK image by
digest, clang 18 for libfuzzer-dotnet, SharpFuzz 2.3.0, downloads checked by SHA-256):

```sh
tools/container.sh tools/gate.sh            # format, build, test, fuzz, audit
tools/container.sh tools/gate.sh test       # one job
FUZZ_SECONDS=600 tools/container.sh tools/gate.sh fuzz
```

| Job | What |
|---|---|
| `format` | `dotnet format --verify-no-changes`: whitespace, style and analyzer diagnostics |
| `build` | the solution with the .NET analyzers (latest-recommended) and the trim/AOT analyzers, warnings as errors |
| `test` | the xunit v3 tests |
| `fuzz` | each SharpFuzz target under libfuzzer-dotnet for `FUZZ_SECONDS` (default 60), `MailAuth.dll` instrumented |
| `audit` | `dotnet list package --vulnerable --include-transitive` |

Consumers build the library from source through a project reference to `src/MailAuth/MailAuth.csproj` and pin a
commit; pass `ArtifactsPath` to keep its build output out of the checkout.

## Contributing

This repository is not accepting contributions at this time: issues and pull requests are not accepted. Report
security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Licence

MIT, see `LICENSE`. Third-party material: `THIRD-PARTY-NOTICES.md`.
