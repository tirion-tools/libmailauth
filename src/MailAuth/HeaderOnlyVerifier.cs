using System.Text;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace MailAuth;

/// <summary>
/// Header-only DKIM for messages whose body is not downloaded yet:
/// DKIM's header signature <c>b=</c> covers the canonicalized signed headers and the DKIM-Signature
/// field with its <c>bh=</c>, nothing from the body, so it is checked from the header block alone. Keys come through
/// the same resolver and per-key RSA validation; MimeKit's DmarcVerifier decides alignment and policy.
/// <para>
/// <c>failed</c>: no counted, aligned signature with a valid <c>b=</c> (DMARC fails without the body). <c>pending</c>:
/// a counted signature with a valid <c>b=</c> (aligned for DMARC pass); its body hash is checked at open.
/// <c>none</c>: no DMARC record and nothing valid, or DNS trouble (never failed). rsa-sha1, RSA &lt; 1,024 bits,
/// revoked or missing keys do not count; an <c>l=</c> counts only when it covers the whole raw body.
/// </para>
/// </summary>
internal sealed class HeaderOnlyVerifier(BrokeredDnsResolver dns, DmarcVerifier dmarc, Func<string, string?, bool> sameOrganization)
{
    public sealed record Result(string Verdict, string Reason, string? Policy, bool Temporary, List<DkimInfo> Dkim);

    /// <summary>One header field: lower-case name and its raw text (Latin-1, CRLF line ends, terminator included).</summary>
    private readonly record struct Field(string Name, string Raw);

    private static List<Field> Fields(ReadOnlySpan<byte> header)
    {
        var text = Encoding.Latin1.GetString(header).Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "\r\n", StringComparison.Ordinal);
        var fields = new List<Field>();
        var cur = new StringBuilder();
        foreach (var line in text.Split("\r\n"))
        {
            if (line.Length == 0) break;   // end of the header block
            if ((line[0] == ' ' || line[0] == '\t') && cur.Length > 0) { cur.Append(line).Append("\r\n"); continue; }
            if (cur.Length > 0) fields.Add(Make(cur.ToString()));
            cur.Clear().Append(line).Append("\r\n");
        }
        if (cur.Length > 0) fields.Add(Make(cur.ToString()));
        return fields;

        static Field Make(string raw)
        {
            int c = raw.IndexOf(':', StringComparison.Ordinal);
            return new Field(c > 0 ? raw[..c].Trim().ToLowerInvariant() : "", raw);
        }
    }

    /// <summary>RFC 6376 §3.4.1 simple / §3.4.2 relaxed header canonicalization of one field.</summary>
    private static string Canon(string raw, bool relaxed)
    {
        if (!relaxed) return raw;
        int c = raw.IndexOf(':', StringComparison.Ordinal);
        string name = raw[..c].Trim().ToLowerInvariant();
        var v = new StringBuilder();
        bool ws = false;
        foreach (char ch in raw[(c + 1)..].Replace("\r\n", "", StringComparison.Ordinal))
        {
            if (ch == ' ' || ch == '\t') { ws = true; continue; }
            if (ws && v.Length > 0) v.Append(' ');
            ws = false;
            v.Append(ch);
        }
        return name + ":" + v + "\r\n";
    }

    /// <summary>The DKIM-Signature field with the value of its b= tag removed (RFC 6376 §3.7), raw otherwise.</summary>
    private static string WithoutB(string raw)
    {
        int c = raw.IndexOf(':', StringComparison.Ordinal) + 1;
        int pos = c;
        while (pos < raw.Length)
        {
            int semi = raw.IndexOf(';', pos);
            int end = semi < 0 ? raw.Length : semi;
            int eq = raw.IndexOf('=', pos);
            if (eq > 0 && eq < end && raw[pos..eq].Trim(' ', '\t', '\r', '\n') == "b")
            {
                int keep = end;
                if (semi < 0) while (keep > eq + 1 && (raw[keep - 1] == '\r' || raw[keep - 1] == '\n')) keep--;
                return raw[..(eq + 1)] + raw[keep..];
            }
            pos = end + 1;
        }
        return raw;
    }

    private static AsymmetricKeyParameter? RsaKey(byte[] der)
    {
        try { return PublicKeyFactory.CreateKey(der); }
        catch (Exception) { }
        try
        {
            var s = RsaPublicKeyStructure.GetInstance(Asn1Object.FromByteArray(der));
            return new RsaKeyParameters(false, s.Modulus, s.PublicExponent);
        }
        catch (Exception) { return null; }
    }

    public Result Verify(MimeMessage msg, ReadOnlySpan<byte> header, long size)
    {
        var fields = Fields(header);
        var dkim = new List<DkimInfo>();
        int fromCount = fields.Count(f => f.Name == "from");
        if (fromCount != 1)
            return new Result(fromCount == 0 ? "none" : "failed", $"{fromCount} From headers", null, false, dkim);
        string? author = msg.From.Mailboxes.FirstOrDefault()?.Domain?.ToLowerInvariant().TrimEnd('.');
        long bodyLen = Math.Max(0, size - header.Length);
        string[] listFields = fields.Where(f => f.Name.StartsWith("list-", StringComparison.Ordinal)).Select(f => f.Name).Distinct().ToArray();
        var results = new List<DkimSignatureValidationResult>();
        var mimeSigHeaders = msg.Headers.Where(h => h.Id == HeaderId.DkimSignature).ToList();
        var dkimFields = fields.Select((f, i) => (f, i)).Where(x => x.f.Name == "dkim-signature").Take(AuthEvaluator.MaxDkimSignatures).ToList();
        for (int k = 0; k < dkimFields.Count && k < mimeSigHeaders.Count; k++)
        {
            var (field, index) = dkimFields[k];
            var tags = Tags.Parse(field.Raw[(field.Raw.IndexOf(':', StringComparison.Ordinal) + 1)..]);
            string d = tags.GetValueOrDefault("d", "").ToLowerInvariant(), s = tags.GetValueOrDefault("s", ""), a = tags.GetValueOrDefault("a", "").ToLowerInvariant();
            string status = "fail";
            var signed = tags.GetValueOrDefault("h", "").Split(':').Select(h => h.Trim().ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
            if (tags.GetValueOrDefault("v") != "1" || d.Length == 0 || s.Length == 0 || !tags.ContainsKey("bh") || !tags.ContainsKey("b") || !tags.ContainsKey("h"))
                status = "permerror";
            else if (!signed.Contains("from"))
                status = "permerror";
            else if (a != "rsa-sha256" && a != "ed25519-sha256") { }
            else if (tags.TryGetValue("l", out var ls) && (!long.TryParse(ls, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long l) || l < bodyLen)) { }
            else
            {
                var answer = dns.QueryTxt(s + "._domainkey." + d);
                if (answer.Status == DnsQueryStatus.TemporaryFailure) status = "temperror";
                else if (answer.Status == DnsQueryStatus.Success && answer.Records.Count > 0)
                {
                    using (new KeyValidation.Scope(true)) status = Check(field, index, fields, tags, a, answer.Records[0]);
                }
            }
            if (AuthEvaluator.TryLdh(d, out var dn))
                dkim.Add(new DkimInfo(dn, status, signed.Contains("from"), listFields.Length > 0 && listFields.All(signed.Contains)));
            // A temporary failure counts only for the From domain's organization (see AuthEvaluator.LocalVerify).
            var st = status switch
            {
                "pass" => DkimSignatureStatus.Pass,
                "temperror" when sameOrganization(d, author) => DkimSignatureStatus.TempError,
                _ => DkimSignatureStatus.Fail,
            };
            results.Add(new DkimSignatureValidationResult(st, d, s, mimeSigHeaders[k]));
        }
        var dm = dmarc.Verify(msg, results, null!);
        string? policy = dm.Status == DmarcStatus.None ? "absent" : dm.Policy?.ToString().ToLowerInvariant() switch
        {
            "none" => "none", "quarantine" => "quarantine", "reject" => "reject", _ => null,
        };
        bool anyPass = results.Any(r => r.Status == DkimSignatureStatus.Pass);
        return dm.Status switch
        {
            DmarcStatus.Pass => new Result("pending", $"aligned signature d={dm.AlignedDkimResult?.Domain} with valid b=; body hash checked at open", policy, false, dkim),
            DmarcStatus.Fail => new Result("failed", $"no aligned signature with a valid b= (p={policy}); decided without the body", policy, false, dkim),
            DmarcStatus.TempError => new Result("none", "temporary DNS failure; retried at next sync", policy, true, dkim),
            DmarcStatus.PermError => new Result("none", "DMARC permerror", policy, false, dkim),
            _ when anyPass => new Result("pending", "valid b= without a DMARC record; body hash checked at open", policy, false, dkim),
            _ when results.Any(r => r.Status == DkimSignatureStatus.TempError) => new Result("none", "temporary DNS failure; retried at next sync", policy, true, dkim),
            _ => new Result("none", results.Count == 0 ? "unsigned, no DMARC record" : "no valid signature, no DMARC record", policy, false, dkim),
        };
    }

    private static string Check(Field sigField, int sigIndex, List<Field> fields, Dictionary<string, string> tags, string alg, string record)
    {
        var kt = Tags.Parse(record);
        string p = kt.GetValueOrDefault("p", "");
        if (p.Length == 0) return "fail";   // revoked
        string kk = kt.GetValueOrDefault("k", "rsa").ToLowerInvariant();
        if ((alg == "rsa-sha256") != (kk == "rsa")) return "fail";
        if (kt.TryGetValue("h", out var kh) && !kh.Split(':').Any(x => x.Trim().Equals("sha256", StringComparison.OrdinalIgnoreCase))) return "fail";
        string[] c = tags.GetValueOrDefault("c", "simple/simple").ToLowerInvariant().Split('/');
        bool relaxed = c[0] == "relaxed";
        // h= selection: each name takes the last not-yet-used instance (RFC 6376 §5.4.2); a name with no
        // instance left contributes nothing (oversigning).
        var used = new HashSet<int>();
        var data = new StringBuilder();
        foreach (var name in tags["h"].Split(':').Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 0))
        {
            for (int i = fields.Count - 1; i >= 0; i--)
            {
                if (i == sigIndex || used.Contains(i) || fields[i].Name != name) continue;
                used.Add(i);
                data.Append(Canon(fields[i].Raw, relaxed));
                break;
            }
        }
        string self = Canon(WithoutB(sigField.Raw), relaxed);
        if (self.EndsWith("\r\n", StringComparison.Ordinal)) self = self[..^2];
        data.Append(self);
        byte[] input = Encoding.Latin1.GetBytes(data.ToString());
        byte[] sig, keyBytes;
        try
        {
            sig = Convert.FromBase64String(tags["b"]);
            keyBytes = Convert.FromBase64String(p);
        }
        catch (FormatException) { return "fail"; }
        if (kk == "rsa")
        {
            if (RsaKey(keyBytes) is not RsaKeyParameters rsa || rsa.Modulus.BitLength < 1024) return "fail";
            var v = new RsaDigestSigner(new Sha256Digest());
            v.Init(false, rsa);
            v.BlockUpdate(input, 0, input.Length);
            return v.VerifySignature(sig) ? "pass" : "fail";
        }
        if (kk == "ed25519")
        {
            if (keyBytes.Length != 32) return "fail";
            byte[] hash = System.Security.Cryptography.SHA256.HashData(input);   // RFC 8463 signs the SHA-256 hash
            var v = new Ed25519Signer();
            v.Init(false, new Ed25519PublicKeyParameters(keyBytes, 0));
            v.BlockUpdate(hash, 0, hash.Length);
            return v.VerifySignature(sig) ? "pass" : "fail";
        }
        return "fail";
    }
}
