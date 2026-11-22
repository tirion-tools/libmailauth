using MimeKit;
using MimeKit.Cryptography;

namespace MailAuth;

/// <summary>One DKIM signature of an <see cref="AuthOutcome"/>.</summary>
public sealed record DkimInfo(string D, string Result, bool SignsFrom, bool SignsListFields);

/// <summary>The authentication verdict of one message.</summary>
public sealed class AuthOutcome
{
    /// <summary><c>provider_sealed</c>, <c>trusted_arh</c>, <c>local</c> or <c>none</c>.</summary>
    public string Source { get; set; } = "none";
    /// <summary><c>verified</c>, <c>verified_forwarded</c>, <c>unaligned</c>, <c>failed</c> or <c>none</c>.</summary>
    public string Verdict { get; set; } = "none";
    /// <summary>DNS trouble decided the verdict; evaluate again later.</summary>
    public bool Temporary { get; set; }
    /// <summary>Header-only: a valid aligned header signature (or sealed results of a listed sealer) is checked once the body is there.</summary>
    public bool PendingOpen { get; set; }
    public string? VerifiedDomain { get; set; }
    public string? ViaDomain { get; set; }
    /// <summary><c>none</c>, <c>quarantine</c>, <c>reject</c>, <c>absent</c> or null.</summary>
    public string? Policy { get; set; }
    /// <summary>Authentication-Results (and verdict-relevant headers) present but not trusted.</summary>
    public int Ignored { get; set; }
    public string Reason { get; set; } = "";
    public List<DkimInfo> Dkim { get; set; } = [];
    /// <summary>No DKIM-Signature, local DMARC fail, no trusted results (the final verdict depends on signing history).</summary>
    public bool UnsignedDmarcFail { get; set; }
    /// <summary>Local DMARC fail where every signature's key record is missing or revoked (final verdict depends on age).</summary>
    public bool KeyGone { get; set; }
    /// <summary>An aligned DKIM pass, or a valid aligned header signature, for the From organizational domain.</summary>
    public bool SigningEvidence { get; set; }
    /// <summary>The local verdict is failed because DMARC failed (not two From headers).</summary>
    public bool DmarcFailed { get; set; }
    /// <summary>The provider-sealed AAR the verdict came from, if any (provider verdict methods read it).</summary>
    public AuthenticationResults? SealedAar { get; set; }
}

/// <summary>
/// The receiving client's authentication rule over MimeKit 5's DkimVerifier, ArcVerifier and DmarcVerifier:
/// <list type="number">
/// <item>Provider-sealing account: the ARC-Authentication-Results sealed by the provider (highest such instance, chain
///   pass, authserv-id of the account); otherwise local verification.</item>
/// <item>Stamping server: the topmost Authentication-Results with the account's authserv-id; otherwise local.</item>
/// <item>Local DKIM + DMARC: at most 5 signatures, RSA &lt; 1,024 bits, rsa-sha1 (MimeKit) and an <c>l=</c> shorter than the
///   body do not count; two From headers fail; DNS trouble gives none (temporary), never failed. A trusted forwarder's
///   own sealed AAR may turn a DMARC failure into verified_forwarded only with a sealer DKIM signature.</item>
/// </list>
/// One instance per thread; not thread-safe.
/// </summary>
public sealed class AuthEvaluator
{
    public const int MaxDkimSignatures = 5;
    public const int MaxOrgCache = 4096;
    private readonly DkimVerifier _dkim;
    private readonly ArcVerifier _arc;
    private readonly DmarcVerifier _dmarc;
    private readonly HeaderOnlyVerifier _headerOnly;
    private readonly BrokeredDnsResolver _dns;
    private readonly Func<string, string?> _registrable;
    private readonly Dictionary<string, string> _orgDomains = new(StringComparer.Ordinal);

    /// <param name="dns">The resolver every verifier and the header-only check use.</param>
    /// <param name="registrableDomain">The registrable domain (eTLD+1, Public Suffix List) of a lower-case host, or null
    /// for a public suffix; used without DNS lookups for the history and DNS-trouble organization checks.</param>
    public AuthEvaluator(BrokeredDnsResolver dns, Func<string, string?> registrableDomain)
    {
        _dns = dns;
        _registrable = registrableDomain;
        _dkim = new DkimVerifier(dns) { MaxSignatures = MaxDkimSignatures, MinimumRsaKeyLength = 1024 };
        _arc = new ArcVerifier(dns);
        _dmarc = new DmarcVerifier(dns, _dkim) { MaxDkimSignatures = MaxDkimSignatures };
        _headerOnly = new HeaderOnlyVerifier(dns, _dmarc, SameOrganization);
    }

    // ------------------------------------------------------------------ helpers

    private static string? Prop(AuthenticationMethodResult m, string ptype, string prop) =>
        m.Properties.FirstOrDefault(p => string.Equals(p.PropertyType, ptype, StringComparison.OrdinalIgnoreCase)
                                         && string.Equals(p.Property, prop, StringComparison.OrdinalIgnoreCase))?.Value;

    private static bool Is(string? a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    /// <summary>Alignment used only when no DMARC record applies: same domain or one a subdomain of the other.</summary>
    public static bool Related(string a, string b)
    {
        a = a.ToLowerInvariant().TrimEnd('.');
        b = b.ToLowerInvariant().TrimEnd('.');
        return a == b || a.EndsWith("." + b, StringComparison.Ordinal) || b.EndsWith("." + a, StringComparison.Ordinal);
    }

    internal static bool TryLdh(string? s, out string norm)
    {
        norm = (s ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (norm.Length is 0 or > 253) return false;
        foreach (var label in norm.Split('.'))
            if (label.Length is 0 or > 63 || label.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_'))) return false;
        return true;
    }

    private static string? PolicyName(string? p) => p?.ToLowerInvariant() switch
    {
        "none" => "none",
        "quarantine" => "quarantine",
        "reject" => "reject",
        _ => null,
    };

    /// <summary>Bytes of the header block of <paramref name="raw"/>, including the empty line that ends it.</summary>
    internal static int HeaderLength(ReadOnlySpan<byte> raw)
    {
        int end = raw.IndexOf("\r\n\r\n"u8);
        if (end >= 0) return end + 4;
        end = raw.IndexOf("\n\n"u8);
        return end >= 0 ? end + 2 : raw.Length;
    }

    /// <summary>Canonicalized body length (RFC 6376 §3.4.3 simple, §3.4.4 relaxed); MimeKit's filters are internal.</summary>
    internal static long CanonicalBodyLength(ReadOnlySpan<byte> raw, bool relaxed)
    {
        int start = HeaderLength(raw);
        long total = 0, pendingEmpty = 0;
        int pos = start;
        while (pos < raw.Length)
        {
            int nl = raw[pos..].IndexOf((byte)'\n');
            int stop = nl < 0 ? raw.Length : pos + nl;
            int lineEnd = stop > pos && raw[stop - 1] == '\r' ? stop - 1 : stop;
            long len;
            if (!relaxed) len = lineEnd - pos;
            else
            {
                len = 0;
                bool ws = false;
                for (int k = pos; k < lineEnd; k++)
                {
                    byte c = raw[k];
                    if (c == ' ' || c == '\t') { ws = true; continue; }
                    if (ws) len++;
                    ws = false;
                    len++;
                }
            }
            // Trailing empty lines are removed (both rules): count them only once a non-empty line follows.
            if (len == 0) pendingEmpty++;
            else
            {
                total += pendingEmpty * 2 + len + 2;
                pendingEmpty = 0;
            }
            pos = nl < 0 ? raw.Length : stop + 1;
        }
        return total == 0 && !relaxed ? 2 : total;
    }

    // ------------------------------------------------------------------ verdict from AR results

    private sealed record ArVerdict(string Verdict, string Reason, string? Policy);

    private static ArVerdict FromResults(AuthenticationResults ar, string? authorDomain, int fromCount, bool sealedResults)
    {
        if (fromCount != 1) return new("failed", $"{fromCount} From headers", null);
        var dmarc = ar.Results.FirstOrDefault(m => Is(m.Method, "dmarc"));
        string? policy = null;
        if (dmarc != null)
        {
            string? hf = Prop(dmarc, "header", "from");
            if (hf == null || authorDomain == null || Is(hf, authorDomain))
            {
                policy = PolicyName(Prop(dmarc, "policy", "dmarc"));
                // Microsoft 365 records the applied action; only inside the provider's sealed results.
                if (policy == null && sealedResults && dmarc.Action != null)
                    policy = dmarc.Action.ToLowerInvariant().TrimStart('o') switch { "reject" => "reject", "quarantine" => "quarantine", _ => null };
                switch (dmarc.Result?.ToLowerInvariant())
                {
                    case "pass": return new("verified", "dmarc=pass (" + ar.AuthenticationServiceIdentifier + ")", policy);
                    case "fail": return new("failed", "dmarc=fail (" + ar.AuthenticationServiceIdentifier + ")", policy);
                    case "temperror":
                    case "permerror": return new("none", "dmarc=" + dmarc.Result, policy);
                }
            }
        }
        if (sealedResults && ar.Results.Any(m => Is(m.Method, "compauth") && Is(m.Result, "fail")))
            return new("failed", "compauth=fail in the provider's sealed results", policy);
        bool anyPass = false, aligned = false;
        foreach (var m in ar.Results.Where(m => Is(m.Method, "dkim") && Is(m.Result, "pass")))
        {
            anyPass = true;
            string? d = Prop(m, "header", "d") ?? Prop(m, "header", "i")?.Split('@').Last();
            if (d != null && authorDomain != null && Related(d, authorDomain)) aligned = true;
        }
        if (aligned) return new("verified", "dkim=pass aligned, no DMARC record", policy);
        if (anyPass) return new("unaligned", "dkim=pass for another domain", policy);
        return new("none", "no passing authentication in trusted results", policy);
    }

    private static void FillFromResults(AuthOutcome o, AuthenticationResults ar, ArVerdict v, string? author)
    {
        o.Verdict = v.Verdict;
        o.Policy = v.Policy;
        o.Reason = v.Reason;
        foreach (var m in ar.Results.Where(m => Is(m.Method, "dkim")))
        {
            if (o.Dkim.Count >= MaxDkimSignatures) break;
            string? d = Prop(m, "header", "d") ?? Prop(m, "header", "i")?.Split('@').Last();
            if (!TryLdh(d, out var dn)) continue;
            o.Dkim.Add(new DkimInfo(dn, (m.Result ?? "").ToLowerInvariant(), false, false));
        }
        if (o.Verdict == "verified") o.VerifiedDomain = author;
        else if (o.Verdict == "unaligned") o.ViaDomain = o.Dkim.FirstOrDefault(x => x.Result == "pass")?.D;
    }

    // ------------------------------------------------------------------ evaluation

    private static (AuthenticationResults? trusted, int ignored) TrustedArh(MimeMessage msg, AuthPolicy policy)
    {
        AuthenticationResults? trusted = null;
        int ignored = 0;
        foreach (var h in msg.Headers)
        {
            if (h.Id != HeaderId.AuthenticationResults) continue;
            if (trusted == null && policy.AuthservId != null && AuthenticationResults.TryParse(h.RawValue, out var ar)
                && AuthPolicy.Matches(policy.AuthservId, ar.AuthenticationServiceIdentifier))
                trusted = ar;
            else ignored++;
        }
        return (trusted, ignored);
    }

    private sealed record ArcInfo(bool Pass, List<(int I, string D, AuthenticationResults? Aar)> Instances);

    private ArcInfo Arc(MimeMessage msg)
    {
        ArcValidationResult res;
        using (new KeyValidation.Scope(true)) res = _arc.Verify(msg);
        var aars = new Dictionary<int, AuthenticationResults>();
        foreach (var h in msg.Headers.Where(h => h.Id == HeaderId.ArcAuthenticationResults))
            if (AuthenticationResults.TryParse(h.RawValue, out var aar) && aar.Instance.HasValue) aars.TryAdd(aar.Instance.Value, aar);
        var inst = new List<(int, string, AuthenticationResults?)>();
        foreach (var s in res.Seals ?? [])
        {
            var t = Tags.Parse(s.Header.Value);
            _ = int.TryParse(t.GetValueOrDefault("i"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int i);
            inst.Add((i, t.GetValueOrDefault("d", "").ToLowerInvariant(), aars.GetValueOrDefault(i)));
        }
        return new ArcInfo(res.Chain == ArcSignatureValidationResult.Pass, inst);
    }

    /// <summary>The highest instance sealed by one of <paramref name="sealers"/> with an AAR, in a chain that validates.</summary>
    private static (int I, string D, AuthenticationResults Aar)? SealedBy(ArcInfo? arc, string[] sealers)
    {
        if (arc is not { Pass: true }) return null;
        foreach (var x in arc.Instances.OrderByDescending(x => x.I))
            if (x.Aar != null && sealers.Contains(x.D)) return (x.I, x.D, x.Aar);
        return null;
    }

    /// <summary>Full verification: <paramref name="raw"/> is the whole message.</summary>
    /// <param name="deliveredAt">When the receiving server delivered the message (IMAP INTERNALDATE), Unix seconds; a DKIM
    /// signature's <c>x=</c> is judged at that time (<see cref="DeliveryTimeDkim"/>). Null judges it now.</param>
    public AuthOutcome Evaluate(MimeMessage msg, ReadOnlySpan<byte> raw, AuthPolicy policy, long? deliveredAt = null) =>
        History(msg, EvaluateCore(msg, raw, policy, deliveredAt));

    /// <summary>Same organization for the history rules: equal domains or equal registrable domains (PSL).</summary>
    private bool SameOrg(string d, string? author) =>
        author != null && (string.Equals(d, author, StringComparison.OrdinalIgnoreCase)
                           || (_registrable(d.ToLowerInvariant().TrimEnd('.')) is { } a && a == _registrable(author)));

    /// <summary>
    /// The flags the caller's signing-history rules need: unsigned local DMARC failure,
    /// signed with every key gone, and signing evidence for the From organization.
    /// </summary>
    private AuthOutcome History(MimeMessage msg, AuthOutcome o)
    {
        int fromCount = msg.Headers.Count(h => h.Id == HeaderId.From);
        string? author = fromCount == 1 ? Author(msg) : null;
        o.SigningEvidence = author != null && o.Dkim.Any(k => k.Result == "pass" && SameOrg(k.D, author));
        if (o.Source != "local" || o.Verdict != "failed" || author == null || !o.DmarcFailed) return o;
        var sigs = msg.Headers.Where(h => h.Id == HeaderId.DkimSignature).ToList();
        if (sigs.Count == 0)
        {
            o.UnsignedDmarcFail = true;
            return o;
        }
        // The signatures that could have let DMARC pass are the From organization's; an unaligned signature, valid or
        // not, neither helps nor hurts (a sender could leave it out). Without any, every signature counts.
        var counted = sigs.Take(MaxDkimSignatures).Select(h => Tags.Parse(h.Value)).ToList();
        var own = counted.Where(t => TryLdh(t.GetValueOrDefault("d"), out var d) && SameOrg(d, author)).ToList();
        o.KeyGone = (own.Count > 0 ? own : counted).All(t =>
            TryLdh(t.GetValueOrDefault("d"), out var d) && TryLdh(t.GetValueOrDefault("s"), out var sel)
            && _dns.KeyState(sel + "._domainkey." + d) is KeyRecordState.Missing or KeyRecordState.Revoked);
        return o;
    }

    private AuthOutcome EvaluateCore(MimeMessage msg, ReadOnlySpan<byte> raw, AuthPolicy policy, long? deliveredAt)
    {
        var o = new AuthOutcome();
        int fromCount = msg.Headers.Count(h => h.Id == HeaderId.From);
        string? author = fromCount == 1 ? Author(msg) : null;
        var (designArh, ignored) = TrustedArh(msg, policy);
        o.Ignored = ignored;
        ArcInfo? arc = policy.ProviderSealers.Length > 0 || policy.ForwarderSealers.Length > 0 ? Arc(msg) : null;

        if (policy.AuthservId != null && policy.ProviderSealers.Length > 0)
        {
            if (SealedBy(arc, policy.ProviderSealers) is { } s && AuthPolicy.Matches(policy.AuthservId, s.Aar.AuthenticationServiceIdentifier))
            {
                o.Source = "provider_sealed";
                o.SealedAar = s.Aar;
                FillFromResults(o, s.Aar, FromResults(s.Aar, author, fromCount, sealedResults: true), author);
                o.Reason = $"ARC-Authentication-Results i={s.I} sealed by {s.D}: {o.Reason}";
                return o;
            }
            if (designArh != null) o.Ignored++;   // a plain Authentication-Results is not trusted for a sealing provider
        }
        else if (policy.AuthservId != null && designArh != null)
        {
            o.Source = "trusted_arh";
            FillFromResults(o, designArh, FromResults(designArh, author, fromCount, sealedResults: false), author);
            return o;
        }
        LocalVerify(o, msg, raw, author, fromCount, policy, arc, deliveredAt);
        return o;
    }

    private static string? Author(MimeMessage msg)
    {
        var d = msg.From.Mailboxes.FirstOrDefault()?.Domain;
        return d == null ? null : d.ToLowerInvariant().TrimEnd('.');
    }

    private static bool SignsAll(Dictionary<string, string> tags, string[] fields)
    {
        var signed = tags.GetValueOrDefault("h", "").Split(':').Select(x => x.Trim().ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        return fields.All(signed.Contains);
    }

    private static readonly string[] FromOnly = ["from"];

    private static string[] ListFields(MimeMessage msg) =>
        msg.Headers.Where(h => h.Field.StartsWith("List-", StringComparison.OrdinalIgnoreCase))
                   .Select(h => h.Field.ToLowerInvariant()).Distinct().ToArray();

    private static string DkimResultName(DkimSignatureStatus s) => s switch
    {
        DkimSignatureStatus.Pass => "pass",
        DkimSignatureStatus.Fail => "fail",
        DkimSignatureStatus.TempError => "temperror",
        DkimSignatureStatus.PermError => "permerror",
        _ => "neutral",
    };

    /// <summary>For DNS-trouble decisions only: same registrable domain (PSL), no lookups needed.</summary>
    private bool SameOrganization(string d, string? author) =>
        author != null && (Related(d, author) || (_registrable(d) is { } a && a == _registrable(author)));

    private void LocalVerify(AuthOutcome o, MimeMessage msg, ReadOnlySpan<byte> raw, string? author, int fromCount, AuthPolicy policy, ArcInfo? arc,
                             long? deliveredAt)
    {
        o.Source = "local";
        var results = new List<DkimSignatureValidationResult>();
        var tagsList = new List<Dictionary<string, string>>();
        var listFields = ListFields(msg);
        var relaxedLen = new long?[2];
        List<(HeaderOnlyVerifier.Field Field, int Index)>? sigFields = null;   // the raw DKIM-Signature fields, when needed
        List<HeaderOnlyVerifier.Field>? fields = null;
        int k = 0;
        foreach (var h in msg.Headers.Where(h => h.Id == HeaderId.DkimSignature).Take(MaxDkimSignatures))
        {
            DkimSignatureValidationResult r;
            using (new KeyValidation.Scope(true)) r = _dkim.Verify(msg, h);
            var tags = Tags.Parse(h.Value);
            if (DeliveryTimeDkim.ExpiredSinceDelivery(r, tags, deliveredAt))
            {
                fields ??= HeaderOnlyVerifier.Fields(raw[..HeaderLength(raw)]);
                sigFields ??= fields.Select((f, i) => (f, i)).Where(x => x.f.Name == "dkim-signature").ToList();
                if (k < sigFields.Count) r = DeliveryTimeDkim.Verify(_dns, msg, h, fields, sigFields[k].Index);
            }
            k++;
            if (r.Status == DkimSignatureStatus.Pass && tags.TryGetValue("l", out var ls)
                && long.TryParse(ls, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long l))
            {
                bool relaxedBody = Is(tags.GetValueOrDefault("c", "simple/simple").Split('/').ElementAtOrDefault(1), "relaxed");
                long len = relaxedLen[relaxedBody ? 1 : 0] ??= CanonicalBodyLength(raw, relaxedBody);
                // Content after l= bytes is unauthenticated: such a signature does not count.
                if (len > l)
                    r = new DkimSignatureValidationResult(DkimSignatureStatus.Fail, r.Domain ?? tags.GetValueOrDefault("d", ""), r.Selector ?? tags.GetValueOrDefault("s", ""), h);
            }
            results.Add(r);
            tagsList.Add(tags);
            if (TryLdh(r.Domain ?? tags.GetValueOrDefault("d"), out var dn))
                o.Dkim.Add(new DkimInfo(dn, DkimResultName(r.Status), SignsAll(tags, FromOnly), listFields.Length > 0 && SignsAll(tags, listFields)));
        }
        // A temporary failure counts only where it could decide the verdict: a signature of the From domain's
        // organization. Elsewhere it is a failure, so a sender cannot turn `failed` into `none` with a broken key server.
        var forDmarc = results.Select(r => r.Status == DkimSignatureStatus.TempError && !SameOrganization(r.Domain ?? "", author)
            ? new DkimSignatureValidationResult(DkimSignatureStatus.Fail, r.Domain ?? "", r.Selector ?? "", r.Header) : r).ToList();
        var dm = _dmarc.Verify(msg, forDmarc, null!);
        o.Policy = dm.Status == DmarcStatus.None ? "absent" : PolicyName(dm.Policy?.ToString());

        if (fromCount != 1)
        {
            o.Verdict = fromCount == 0 ? "none" : "failed";
            o.Reason = $"{fromCount} From headers";
        }
        else switch (dm.Status)
            {
                case DmarcStatus.Pass:
                    o.Verdict = "verified";
                    o.Reason = $"DMARC pass, aligned d={dm.AlignedDkimResult?.Domain}";
                    break;
                case DmarcStatus.Fail:
                    o.Verdict = "failed";
                    o.DmarcFailed = true;
                    o.Reason = $"DMARC fail (p={o.Policy})";
                    break;
                case DmarcStatus.TempError:
                    o.Temporary = true;
                    o.Reason = "temporary DNS failure; retried at next sync";
                    break;
                case DmarcStatus.PermError:
                    o.Reason = "DMARC permerror";
                    break;
                default:
                    {
                        var pass = forDmarc.Where(r => r.Status == DkimSignatureStatus.Pass && r.Domain != null).ToList();
                        if (author != null && pass.Any(r => Related(r.Domain!, author)))
                        {
                            o.Verdict = "verified";
                            o.Reason = "DKIM pass aligned, no DMARC record";
                        }
                        else if (pass.Count > 0)
                        {
                            o.Verdict = "unaligned";
                            o.ViaDomain = TryLdh(pass[0].Domain, out var via) ? via : null;
                            o.Reason = "DKIM pass for another domain, no DMARC record";
                        }
                        else if (forDmarc.Any(r => r.Status == DkimSignatureStatus.TempError))
                        {
                            o.Temporary = true;
                            o.Reason = "temporary DNS failure; retried at next sync";
                        }
                        else o.Reason = results.Count == 0 ? "unsigned, no DMARC record" : "no valid signature, no DMARC record";
                        break;
                    }
            }
        if (o.Verdict == "verified") o.VerifiedDomain = author;
        if (o.Verdict == "failed" && author != null && policy.ForwarderSealers.Length > 0 && SealedBy(arc, policy.ForwarderSealers) is { } s)
            Forwarded(o, msg, results, tagsList, s, author, dm, policy);
    }

    /// <summary>
    /// Forwarder binding: only the trusted sealer's own instance counts, and only when its AAR records
    /// dmarc=pass for the same From domain, or (no dmarc result) a dkim=pass aligned with it. Sealer DKIM requirement
    ///: the sealer must also DKIM-sign the message itself (<see cref="SealerSignature"/>).
    /// </summary>
    private void Forwarded(AuthOutcome o, MimeMessage msg, List<DkimSignatureValidationResult> results, List<Dictionary<string, string>> tags,
                           (int I, string D, AuthenticationResults Aar) s, string author, DmarcValidationResult dm, AuthPolicy policy)
    {
        var dmarc = s.Aar.Results.FirstOrDefault(m => Is(m.Method, "dmarc"));
        string? hf = dmarc == null ? null : Prop(dmarc, "header", "from");
        bool dmarcPass = dmarc != null && Is(dmarc.Result, "pass") && Is(hf, author);
        string org = (dm.OrganizationalDomain ?? author).ToLowerInvariant().TrimEnd('.');
        string? alignedD = null;
        if (!dmarcPass && dmarc == null)
            foreach (var m in s.Aar.Results.Where(m => Is(m.Method, "dkim") && Is(m.Result, "pass")))
            {
                string? d = Prop(m, "header", "d")?.ToLowerInvariant().TrimEnd('.');
                if (d != null && (d == org || d.EndsWith("." + org, StringComparison.Ordinal))) { alignedD = d; break; }
            }
        if (!dmarcPass && alignedD == null) return;
        var (signer, refusal) = SealerSignature(msg, results, tags, s.D, author, policy);
        if (signer == null)
        {
            o.Reason += $"; trusted sealer {s.D} not honoured: {refusal}";
            return;
        }
        o.Verdict = "verified_forwarded";
        o.VerifiedDomain = author;
        o.ViaDomain = s.D;
        o.Reason = $"forwarded via {s.D} (ARC i={s.I}, sealer DKIM d={signer}); local {o.Reason}";
    }

    /// <summary>
    /// A passing DKIM signature (after the l= rule) by the sealer's organization or a signing domain the shipped list
    /// pairs with it, whose h= names From and every List-* field the message carries. Tenant signers count only when
    /// d= equals the From domain or equals / is a parent of the List-Id. Returns the signing domain, or null and why.
    /// </summary>
    private (string? D, string Why) SealerSignature(MimeMessage msg, List<DkimSignatureValidationResult> results,
                                                    List<Dictionary<string, string>> tags, string sealer, string author, AuthPolicy policy)
    {
        string org = OrgDomain(sealer);
        var pairs = policy.SealerSigners.GetValueOrDefault(org) ?? [];
        var required = FromOnly.Concat(ListFields(msg)).Distinct().ToArray();
        string? listId = ListId(msg);
        bool Accepted(string d)
        {
            if (!TryLdh(d, out _)) return false;
            string dOrg = OrgDomain(d);
            if (dOrg == org) return true;
            foreach (var p in pairs)
            {
                if (!p.Tenant && dOrg == p.Signer) return true;
                if (p.Tenant && d.EndsWith("." + p.Signer, StringComparison.Ordinal)
                    && (d == author || (listId != null && (listId == d || listId.EndsWith("." + d, StringComparison.Ordinal)))))
                    return true;
            }
            return false;
        }
        string? why = null;
        for (int k = 0; k < results.Count; k++)
        {
            string d = (results[k].Domain ?? tags[k].GetValueOrDefault("d", "")).ToLowerInvariant().TrimEnd('.');
            if (!Accepted(d)) continue;
            if (results[k].Status != DkimSignatureStatus.Pass) { why ??= $"sealer DKIM d={d} {results[k].Status}"; continue; }
            if (!SignsAll(tags[k], required)) { why ??= $"sealer DKIM d={d} does not sign From and every List-* field"; continue; }
            return (d, "");
        }
        return (null, why ?? $"no DKIM signature by {org} or a signer listed for it");
    }

    internal static string? ListId(MimeMessage msg)
    {
        var lid = msg.Headers[HeaderId.ListId];
        if (lid == null) return null;
        int a = lid.IndexOf('<', StringComparison.Ordinal), b = a < 0 ? -1 : lid.IndexOf('>', a + 1);
        if (a < 0 || b < 0 || b - a - 1 is < 1 or > 255) return null;
        var id = lid[(a + 1)..b];
        return id.Any(char.IsWhiteSpace) ? null : id.ToLowerInvariant().TrimEnd('.');
    }

    /// <summary>DMARC organizational domain (RFC 9989 tree walk by MimeKit's DmarcVerifier on a probe message through
    /// the same resolver); the domain itself when no record applies.</summary>
    internal string OrgDomain(string domain)
    {
        if (_orgDomains.TryGetValue(domain, out var org)) return org;
        var probe = new MimeMessage();
        probe.From.Add(new MailboxAddress("", "postmaster@" + domain));
        var dm = _dmarc.Verify(probe, [], null!);
        org = (dm.OrganizationalDomain ?? domain).ToLowerInvariant().TrimEnd('.');
        if (_orgDomains.Count >= MaxOrgCache) _orgDomains.Clear();
        return _orgDomains[domain] = org;
    }

    // ------------------------------------------------------------------ header-only

    /// <summary>
    /// Body not fetched at sync: the header-only verdict
    /// (<see cref="HeaderOnlyVerifier"/>) decides failed now; a valid aligned header signature is pending and checked
    /// at open. The key and policy names are looked up now, so open-time verification runs from the cache.
    /// </summary>
    /// <param name="deliveredAt">See <see cref="Evaluate"/>.</param>
    public AuthOutcome EvaluateHeaderOnly(MimeMessage msg, ReadOnlySpan<byte> header, long size, AuthPolicy policy, long? deliveredAt = null) =>
        History(msg, EvaluateHeaderOnlyCore(msg, header, size, policy, deliveredAt));

    private AuthOutcome EvaluateHeaderOnlyCore(MimeMessage msg, ReadOnlySpan<byte> header, long size, AuthPolicy policy, long? deliveredAt)
    {
        var o = new AuthOutcome();
        int fromCount = msg.Headers.Count(h => h.Id == HeaderId.From);
        string? author = fromCount == 1 ? Author(msg) : null;
        var (designArh, ignored) = TrustedArh(msg, policy);
        o.Ignored = ignored;
        if (policy.AuthservId != null && policy.ProviderSealers.Length == 0 && designArh != null)
        {
            o.Source = "trusted_arh";
            FillFromResults(o, designArh, FromResults(designArh, author, fromCount, sealedResults: false), author);
            return o;
        }
        if (policy.ProviderSealers.Length > 0 && designArh != null) o.Ignored++;
        o.Source = "local";
        var r = _headerOnly.Verify(msg, header, size, deliveredAt);
        o.Policy = r.Policy;
        o.Reason = r.Reason;
        o.Dkim = r.Dkim;
        switch (r.Verdict)
        {
            case "failed": o.Verdict = "failed"; o.DmarcFailed = fromCount == 1; break;
            case "pending": o.PendingOpen = true; break;
            default: o.Temporary = r.Temporary; break;
        }
        // ARC needs the body (the AMS covers it): sealed results of a listed sealer can only be read at open.
        string[] sealers = [.. policy.ProviderSealers, .. policy.ForwarderSealers];
        if (sealers.Length > 0)
        {
            bool listedSeal = false;
            foreach (var h in msg.Headers.Where(h => h.Id is HeaderId.ArcSeal or HeaderId.ArcMessageSignature))
            {
                var t = Tags.Parse(h.Value);
                if (!TryLdh(t.GetValueOrDefault("d"), out var d) || !TryLdh(t.GetValueOrDefault("s"), out var sel)) continue;
                _dns.QueryTxt(sel + "._domainkey." + d);
                if (h.Id == HeaderId.ArcSeal)
                {
                    OrgDomain(d);
                    listedSeal |= sealers.Contains(d);
                }
            }
            if (listedSeal && fromCount == 1 && o.Verdict != "verified")
            {
                o.Verdict = "none";
                o.PendingOpen = true;
                o.Temporary = false;
                o.Reason += "; sealed results of a trusted sealer are checked at open";
            }
        }
        return o;
    }
}
