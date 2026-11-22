using MimeKit;
using MimeKit.Cryptography;

namespace MailAuth;

/// <summary>
/// DKIM signature expiry (<c>x=</c>) judged at the message's delivery time.
/// <para>
/// MimeKit 5's <see cref="DkimVerifier"/> compares <c>x=</c> with the current clock and stops with PermError
/// "signature expired" before it looks up the key. Email service providers commonly sign with <c>x=</c> two hours
/// after <c>t=</c>, so a client that first sees a message later (a first sync of an existing mailbox, a laptop that was
/// off) would count a signature that verified at delivery as broken, and DMARC would fail under the sender's own
/// reject policy. RFC 6376 §3.5 leaves expiry to the verifier; a receiving client judges it as of delivery, the time
/// the receiving server verified it. A signature already expired at delivery stays PermError.
/// </para>
/// <para>
/// A signature MimeKit refused only for expiry is checked here as MimeKit checks it, without the clock: the key through
/// the same resolver and per-key validation, the header signature <c>b=</c> with
/// <see cref="HeaderOnlyVerifier.Check"/>, the body hash <c>bh=</c> with MimeKit's own <c>VerifyBodyHash</c>.
/// </para>
/// </summary>
internal sealed class DeliveryTimeDkim : DkimVerifierBase
{
    /// <summary>MimeKit's reason for a signature it refused on <c>x=</c> alone (its other checks passed before).</summary>
    internal const string ExpiredReason = "signature expired";

    // Never constructed: only MimeKit's protected static body hash is used.
    private DeliveryTimeDkim(IDnsResolver resolver) : base(resolver) { }

    /// <summary>
    /// True when MimeKit refused <paramref name="r"/> only because <c>x=</c> is before now, and <c>x=</c> is not before
    /// <paramref name="deliveredAt"/> (Unix seconds): the signature has to be judged at delivery.
    /// </summary>
    internal static bool ExpiredSinceDelivery(DkimSignatureValidationResult r, Dictionary<string, string> tags, long? deliveredAt) =>
        deliveredAt is { } t && r.Status == DkimSignatureStatus.PermError && r.Reason == ExpiredReason
        && Expiry(tags) is { } x && x >= t;

    /// <summary>The <c>x=</c> value in Unix seconds, or null when absent or not a plain decimal number.</summary>
    internal static long? Expiry(Dictionary<string, string> tags) =>
        tags.TryGetValue("x", out var xs) && long.TryParse(xs, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long x)
            ? x : null;

    /// <summary>
    /// The result MimeKit would give <paramref name="sig"/> (the <paramref name="sigIndex"/>-th field of the header block
    /// <paramref name="fields"/>) without its clock: TempError on DNS trouble, PermError for a missing or revoked key or a
    /// key that does not suit the signature, else Pass or Fail from the body hash and the header signature.
    /// </summary>
    internal static DkimSignatureValidationResult Verify(BrokeredDnsResolver dns, MimeMessage msg, Header sig, List<HeaderOnlyVerifier.Field> fields, int sigIndex)
    {
        string raw = fields[sigIndex].Raw;
        var tags = Tags.Parse(raw[(raw.IndexOf(':', StringComparison.Ordinal) + 1)..]);
        string d = tags.GetValueOrDefault("d", ""), s = tags.GetValueOrDefault("s", "");
        string a = tags.GetValueOrDefault("a", "").ToLowerInvariant();
        DkimSignatureValidationResult Result(DkimSignatureStatus st) => new(st, d, s, sig);
        DkimSignatureAlgorithm alg;
        if (a == "rsa-sha256") alg = DkimSignatureAlgorithm.RsaSha256;
        else if (a == "ed25519-sha256") alg = DkimSignatureAlgorithm.Ed25519Sha256;
        else return Result(DkimSignatureStatus.PermError);
        var answer = dns.QueryTxt(s + "._domainkey." + d);
        if (answer.Status == DnsQueryStatus.TemporaryFailure) return Result(DkimSignatureStatus.TempError);
        if (answer.Status != DnsQueryStatus.Success || answer.Records.Count == 0) return Result(DkimSignatureStatus.PermError);
        string record = answer.Records[0];
        var kt = Tags.Parse(record);
        if (kt.GetValueOrDefault("p", "").Length == 0) return Result(DkimSignatureStatus.PermError);   // revoked
        // Key flag t=s (RFC 6376 §3.6.1): the i= domain must equal d=.
        if (kt.TryGetValue("t", out var flags) && flags.Split(':').Any(f => f.Trim() == "s") && tags.TryGetValue("i", out var i)
            && !string.Equals(i[(i.LastIndexOf('@') + 1)..].TrimEnd('.'), d.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
            return Result(DkimSignatureStatus.PermError);
        string[] c = tags.GetValueOrDefault("c", "simple/simple").ToLowerInvariant().Split('/');
        var body = c.ElementAtOrDefault(1) == "relaxed" ? DkimCanonicalizationAlgorithm.Relaxed : DkimCanonicalizationAlgorithm.Simple;
        int maxLength = -1;
        if (tags.TryGetValue("l", out var ls) && !int.TryParse(ls, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out maxLength))
            return Result(DkimSignatureStatus.PermError);
        var options = FormatOptions.Default.Clone();
        options.NewLineFormat = NewLineFormat.Dos;
        if (!VerifyBodyHash(options, msg, alg, body, maxLength, tags.GetValueOrDefault("bh", "")))
            return Result(DkimSignatureStatus.Fail);
        string header;
        using (new KeyValidation.Scope(true)) header = HeaderOnlyVerifier.Check(fields[sigIndex], sigIndex, fields, tags, a, record);
        return Result(header == "pass" ? DkimSignatureStatus.Pass : DkimSignatureStatus.Fail);
    }
}
