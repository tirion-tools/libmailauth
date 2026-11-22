using System.Text;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace MailAuth.Tests;

/// <summary>
/// DKIM <c>x=</c> judged at delivery (<see cref="DeliveryTimeDkim"/>) and the key-gone flag over the From organization's
/// signatures. Messages are signed here with fresh keys under <c>.test</c> domains; DNS is a dictionary.
/// </summary>
public sealed class DeliveryTimeTests
{
    private const long Day = 86_400;
    private static readonly AsymmetricCipherKeyPair EspKey = NewKey(), SenderKey = NewKey();

    private static AsymmetricCipherKeyPair NewKey()
    {
        var g = new RsaKeyPairGenerator();
        g.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return g.GenerateKeyPair();
    }

    private static string KeyRecord(AsymmetricCipherKeyPair k) =>
        "v=DKIM1; k=rsa; p=" + Convert.ToBase64String(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(k.Public).GetDerEncoded());

    /// <summary>A signer whose t= is fixed in the past, as when a message is verified long after it was signed.</summary>
    private sealed class PastSigner(AsymmetricKeyParameter key, string domain, string selector, long t) : DkimSigner(key, domain, selector)
    {
        protected override long GetTimestamp() => t;
    }

    /// <summary>A TXT transport over a fixed zone; names listed in <c>temp</c> answer Temp.</summary>
    private sealed class DictTransport(Dictionary<string, string> zone, params string[] temp) : ITxtTransport
    {
        public List<string> Asked { get; } = [];

        public TxtReply Ask(string name, CancellationToken ct)
        {
            Asked.Add(name);
            if (temp.Contains(name)) return new TxtReply(TxtStatus.Temp, [], 0);
            return zone.TryGetValue(name, out var r) ? new TxtReply(TxtStatus.Ok, [r], 300) : new TxtReply(TxtStatus.NxDomain, [], 300);
        }
    }

    private static Dictionary<string, string> Zone(string? senderKey = null) => new(StringComparer.Ordinal)
    {
        ["_dmarc.shop.test"] = "v=DMARC1; p=reject",
        ["mg._domainkey.shop.test"] = KeyRecord(EspKey),
        ["s1._domainkey.esp.test"] = senderKey ?? KeyRecord(SenderKey),
    };

    private static readonly long Signed = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 30 * Day;

    /// <summary>A receipt from shop.test signed by its ESP with x= two hours after t= (Mailgun's habit), long ago.</summary>
    private static byte[] Receipt(bool tamper = false, bool espSignature = false)
    {
        var msg = new MimeMessage();
        msg.From.Add(new MailboxAddress("Shop", "no-reply@shop.test"));
        msg.To.Add(new MailboxAddress("", "someone@example.test"));
        msg.Subject = "Your receipt";
        msg.Date = DateTimeOffset.FromUnixTimeSeconds(Signed);
        msg.MessageId = "receipt-1@shop.test";
        msg.Body = new TextPart("plain") { Text = "Thanks for riding.\r\n" };
        var signer = new PastSigner(EspKey.Private, "shop.test", "mg", Signed)
        {
            SignaturesExpireAfter = TimeSpan.FromHours(2),
            HeaderCanonicalizationAlgorithm = DkimCanonicalizationAlgorithm.Relaxed,
            BodyCanonicalizationAlgorithm = DkimCanonicalizationAlgorithm.Relaxed,
        };
        HeaderId[] signedHeaders = [HeaderId.From, HeaderId.To, HeaderId.Subject, HeaderId.Date, HeaderId.MessageId];
        signer.Sign(msg, signedHeaders);
        if (espSignature) new PastSigner(SenderKey.Private, "esp.test", "s1", Signed).Sign(msg, signedHeaders);
        using var ms = new MemoryStream();
        msg.WriteTo(FormatOptions.Default, ms);
        var raw = ms.ToArray();
        return tamper ? Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(raw).Replace("Thanks for riding.", "Thanks for riding!", StringComparison.Ordinal)) : raw;
    }

    private static AuthOutcome Run(byte[] raw, long? deliveredAt, Dictionary<string, string>? zone = null, bool full = true, params string[] temp)
    {
        var ev = new AuthEvaluator(new BrokeredDnsResolver([], new DictTransport(zone ?? Zone(), temp), _ => { }), EvaluatorTests.Registrable);
        var input = full ? raw : FixtureSet.Header(raw);
        var msg = EvaluatorTests.Parse(input);
        return full ? ev.Evaluate(msg, input, EvaluatorTests.Local, deliveredAt) : ev.EvaluateHeaderOnly(msg, input, raw.LongLength, EvaluatorTests.Local, deliveredAt);
    }

    [Fact]
    public void ExpiredNowButValidAtDelivery_Verifies()
    {
        var o = Run(Receipt(), deliveredAt: Signed + 60);
        Assert.Equal("verified", o.Verdict);
        Assert.Equal("pass", Assert.Single(o.Dkim).Result);
        Assert.True(o.SigningEvidence);
    }

    [Fact]
    public void WithoutADeliveryTime_MimeKitsClockFailsIt()
    {
        // The dogfood false failure: judged now, the ESP's 2-hour x= has long passed and DMARC fails under p=reject.
        var o = Run(Receipt(), deliveredAt: null);
        Assert.Equal("failed", o.Verdict);
        Assert.Equal("reject", o.Policy);
        Assert.Equal("permerror", Assert.Single(o.Dkim).Result);
    }

    [Fact]
    public void ExpiredAtDelivery_StaysPermError()
    {
        var o = Run(Receipt(), deliveredAt: Signed + 3 * 3600);   // delivered after x= (a replay)
        Assert.Equal("failed", o.Verdict);
        Assert.Equal("permerror", Assert.Single(o.Dkim).Result);
    }

    [Fact]
    public void ChangedBody_FailsAtDelivery()
    {
        var o = Run(Receipt(tamper: true), deliveredAt: Signed + 60);
        Assert.Equal("failed", o.Verdict);
        Assert.Equal("fail", Assert.Single(o.Dkim).Result);
    }

    [Fact]
    public void KeyServerTrouble_IsTemporaryNeverFailed()
    {
        var o = Run(Receipt(), deliveredAt: Signed + 60, temp: "mg._domainkey.shop.test");
        Assert.Equal("none", o.Verdict);
        Assert.True(o.Temporary);
        Assert.Equal("temperror", Assert.Single(o.Dkim).Result);
    }

    [Fact]
    public void RevokedKey_IsPermErrorAndKeyGone()
    {
        var zone = Zone();
        zone["mg._domainkey.shop.test"] = "v=DKIM1; k=rsa; p=";
        var o = Run(Receipt(), deliveredAt: Signed + 60, zone);
        Assert.Equal("failed", o.Verdict);
        Assert.Equal("permerror", Assert.Single(o.Dkim).Result);
        Assert.True(o.KeyGone);
    }

    [Fact]
    public void HeaderOnly_JudgesExpiryAtDelivery()
    {
        Assert.True(Run(Receipt(), deliveredAt: Signed + 60, full: false).PendingOpen);
        var expired = Run(Receipt(), deliveredAt: Signed + 3 * 3600, full: false);
        Assert.Equal("failed", expired.Verdict);
        Assert.Equal("permerror", Assert.Single(expired.Dkim).Result);
        // Without a delivery time header-only leaves x= to the check at open, as before.
        Assert.True(Run(Receipt(), deliveredAt: null, full: false).PendingOpen);
    }

    [Fact]
    public void KeyGone_IgnoresAValidUnalignedSignature()
    {
        // The From organization's key was revoked since delivery; the ESP's own signature still verifies. A sender could
        // leave the ESP signature out, so it neither keeps the message failed nor makes it verified.
        var zone = Zone();
        zone["mg._domainkey.shop.test"] = "v=DKIM1; k=rsa; p=";
        var o = Run(Receipt(espSignature: true), deliveredAt: Signed + 60, zone);
        Assert.Equal("failed", o.Verdict);
        Assert.Contains(o.Dkim, d => d.D == "esp.test" && d.Result == "pass");
        Assert.True(o.KeyGone);
    }

    [Fact]
    public void KeyGone_NeedsEveryKeyWhenNoSignatureIsTheFromOrganizations()
    {
        // Only an unaligned signature, still verifying: its key is present, so not gone.
        var zone = Zone();
        zone.Remove("mg._domainkey.shop.test");
        zone["_dmarc.other.test"] = "v=DMARC1; p=reject";
        var raw = Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(Receipt(espSignature: true)).Replace("no-reply@shop.test", "no-reply@other.test", StringComparison.Ordinal));
        var o = Run(raw, deliveredAt: Signed + 60, zone);
        Assert.Equal("failed", o.Verdict);
        Assert.False(o.KeyGone);
    }
}
