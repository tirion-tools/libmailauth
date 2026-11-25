using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace MailAuth.Tests;

/// <summary>
/// DMARC record discovery that fails temporarily (RFC 7489 §6.6.3) next to a DKIM pass: a pass whose <c>d=</c> is the
/// From domain itself is aligned under strict and relaxed <c>adkim</c> (§3.1.1), so it decides the verdict without the
/// record, with the policy left unknown; a pass that is aligned only under relaxed mode (the organizational domain or
/// another subdomain) still waits for the record. The structure of a real case: mail from a subdomain that signs as
/// itself while the subdomain's own DMARC name SERVFAILs (its delegated name servers are broken). Signed here with a
/// fresh key; DNS is a dictionary.
/// </summary>
public sealed class IdenticalDomainTests
{
    private const string From = "sub.example.test";
    private static readonly AsymmetricCipherKeyPair Key = NewKey();

    private static AsymmetricCipherKeyPair NewKey()
    {
        var g = new RsaKeyPairGenerator();
        g.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return g.GenerateKeyPair();
    }

    /// <summary>TXT over a fixed zone; <c>_dmarc.sub.example.test</c> answers Temp (SERVFAIL), as do names in <c>temp</c>.</summary>
    private sealed class Transport(Dictionary<string, string> zone, params string[] temp) : ITxtTransport
    {
        public TxtReply Ask(string name, CancellationToken ct) =>
            name == "_dmarc." + From || temp.Contains(name) ? new TxtReply(TxtStatus.Temp, [], 0)
            : zone.TryGetValue(name, out var r) ? new TxtReply(TxtStatus.Ok, [r], 300)
            : new TxtReply(TxtStatus.NxDomain, [], 300);
    }

    private static Dictionary<string, string> Zone(string signer) => new(StringComparer.Ordinal)
    {
        ["_dmarc.example.test"] = "v=DMARC1; p=reject",   // the organizational domain answers, as in the real case
        ["k1._domainkey." + signer] = "v=DKIM1; k=rsa; p=" + Convert.ToBase64String(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Key.Public).GetDerEncoded()),
    };

    private static byte[] Message(string signer)
    {
        var msg = new MimeMessage();
        msg.From.Add(new MailboxAddress("Store", "news@" + From));
        msg.To.Add(new MailboxAddress("", "someone@reader.test"));
        msg.Subject = "This week";
        msg.Date = DateTimeOffset.UtcNow.AddHours(-1);
        msg.MessageId = "weekly-1@" + From;
        msg.Body = new TextPart("plain") { Text = "New this week.\r\n" };
        new DkimSigner(Key.Private, signer, "k1")
        {
            HeaderCanonicalizationAlgorithm = DkimCanonicalizationAlgorithm.Relaxed,
            BodyCanonicalizationAlgorithm = DkimCanonicalizationAlgorithm.Relaxed,
        }.Sign(msg, [HeaderId.From, HeaderId.To, HeaderId.Subject, HeaderId.Date, HeaderId.MessageId]);
        using var ms = new MemoryStream();
        msg.WriteTo(FormatOptions.Default, ms);
        return ms.ToArray();
    }

    private static AuthOutcome Run(string signer, bool full = true, params string[] temp)
    {
        var raw = Message(signer);
        var ev = new AuthEvaluator(new BrokeredDnsResolver([], new Transport(Zone(signer), temp), _ => { }), EvaluatorTests.Registrable);
        var input = full ? raw : FixtureSet.Header(raw);
        var msg = EvaluatorTests.Parse(input);
        return full ? ev.Evaluate(msg, input, EvaluatorTests.Local) : ev.EvaluateHeaderOnly(msg, input, raw.LongLength, EvaluatorTests.Local);
    }

    [Fact]
    public void IdenticalDomainPass_WithTheDmarcRecordTemporary_IsVerified_PolicyUnknown()
    {
        var o = Run(From);
        Assert.Equal("verified", o.Verdict);
        Assert.False(o.Temporary);
        Assert.Null(o.Policy);   // unknown: no record was read, none is guessed
        Assert.Equal(From, o.VerifiedDomain);
        Assert.Equal("pass", Assert.Single(o.Dkim).Result);
    }

    [Fact]
    public void IdenticalDomainHeaderSignature_WithTheDmarcRecordTemporary_IsPendingAtOpen()
    {
        var o = Run(From, full: false);
        Assert.True(o.PendingOpen);
        Assert.False(o.Temporary);
        Assert.Null(o.Policy);
    }

    [Theory]
    [InlineData("example.test")]        // the organizational domain: aligned only under adkim=r
    [InlineData("other.example.test")]  // another subdomain of the same organization: aligned only under adkim=r
    public void RelaxedOnlyPass_WithTheDmarcRecordTemporary_StaysTemporary(string signer)
    {
        var full = Run(signer);
        Assert.Equal("none", full.Verdict);
        Assert.True(full.Temporary);
        Assert.Equal("pass", Assert.Single(full.Dkim).Result);
        var ho = Run(signer, full: false);
        Assert.Equal("none", ho.Verdict);
        Assert.True(ho.Temporary);
        Assert.False(ho.PendingOpen);
    }

    [Fact]
    public void IdenticalDomainKey_Temporary_StaysTemporary()
    {
        // No pass at all (the key lookup is temporary too): nothing decides the verdict.
        var o = Run(From, true, "k1._domainkey." + From);
        Assert.Equal("none", o.Verdict);
        Assert.True(o.Temporary);
    }
}
