using System.Text;
using Xunit;

namespace MailAuth.Tests;

/// <summary>The resolver's reply mapping and name policy, the tag-list parser, the header-only field split and the
/// provider-verdict grammars.</summary>
public sealed class ParserTests
{
    [Fact]
    public void Resolver_MapsRepliesWithinTheTransportLimits()
    {
        Assert.False(BrokeredDnsResolver.Map(new TxtReply(TxtStatus.Temp, [], 300), 0).Final);
        Assert.False(BrokeredDnsResolver.Map(new TxtReply(TxtStatus.Refused, [], 300), 0).Final);
        Assert.False(BrokeredDnsResolver.Map(new TxtReply(TxtStatus.Ok, Enumerable.Repeat("v=DKIM1", 17).ToArray(), 300), 0).Final);
        Assert.False(BrokeredDnsResolver.Map(new TxtReply(TxtStatus.Ok, [new string('a', 2049)], 300), 0).Final);
        Assert.False(BrokeredDnsResolver.Map(new TxtReply(TxtStatus.Ok, [new string('a', 2048), new string('a', 2048), "a"], 300), 0).Final);
        Assert.False(BrokeredDnsResolver.Map(new TxtReply(TxtStatus.Ok, ["v=DKIM1;\u0001"], 300), 0).Final);
        var ok = BrokeredDnsResolver.Map(new TxtReply(TxtStatus.Ok, ["v=DMARC1; p=reject"], 5), 1000);
        Assert.True(ok.Final);
        Assert.Equal(1000 + BrokeredDnsResolver.MinTtl, ok.Expires);
        Assert.Equal(1000 + BrokeredDnsResolver.MaxTtl, BrokeredDnsResolver.Map(new TxtReply(TxtStatus.NxDomain, [], uint.MaxValue), 1000).Expires);
        Assert.True(BrokeredDnsResolver.TryName("s1._domainkey.Example.COM.", out var n));
        Assert.Equal("s1._domainkey.example.com", n);
        Assert.True(BrokeredDnsResolver.TryName("_dmarc.com", out _));
        Assert.False(BrokeredDnsResolver.TryName("s1._domainkey.com", out _));
        Assert.False(BrokeredDnsResolver.TryName("s1._domainkey.example.local", out _));
        Assert.False(BrokeredDnsResolver.TryName("s1._domainkey.example.123", out _));
        Assert.False(BrokeredDnsResolver.TryName("a b._domainkey.example.com", out _));
        Assert.False(BrokeredDnsResolver.TryName("example.com", out _));
        Assert.False(BrokeredDnsResolver.TryName("_x._domainkey.ex_ample.com", out _));
    }

    [Fact]
    public void Resolver_PersistedRowsAreCheckedLikeReplies()
    {
        Assert.NotNull(BrokeredDnsResolver.FromRow(new TxtCacheRow("_dmarc.bank.test", "ok", "[\"v=DMARC1; p=reject\"]", 10)));
        Assert.NotNull(BrokeredDnsResolver.FromRow(new TxtCacheRow("_dmarc.bank.test", "nxdomain", "[]", 10)));
        Assert.Null(BrokeredDnsResolver.FromRow(new TxtCacheRow("_dmarc.bank.test", "temp", "[]", 10)));
        Assert.Null(BrokeredDnsResolver.FromRow(new TxtCacheRow("_dmarc.bank.test", "nodata", "[\"x\"]", 10)));
        Assert.Null(BrokeredDnsResolver.FromRow(new TxtCacheRow("_dmarc.bank.test", "ok", "{\"a\":1}", 10)));
        Assert.Null(BrokeredDnsResolver.FromRow(new TxtCacheRow("_dmarc.bank.test", "ok", "[1]", 10)));
        Assert.Null(BrokeredDnsResolver.FromRow(new TxtCacheRow("_dmarc.bank.test", "ok", "[\"a\u0001\"]", 10)));
        Assert.Null(BrokeredDnsResolver.FromRow(new TxtCacheRow("_dmarc.bank.test", "ok", "not json", 10)));
    }

    [Fact]
    public void Resolver_KeyStateReadsTheRawRecords()
    {
        var zone = new Answers(new Dictionary<string, TxtReply>(StringComparer.Ordinal)
        {
            ["a._domainkey.bank.test"] = new(TxtStatus.Ok, ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5"], 300),
            ["r._domainkey.bank.test"] = new(TxtStatus.Ok, ["v=DKIM1; p="], 300),
            ["t._domainkey.bank.test"] = new(TxtStatus.Temp, [], 0),
        });
        var dns = new BrokeredDnsResolver([], zone, _ => { });
        foreach (var s in new[] { "a", "r", "m", "t" }) dns.QueryTxt(s + "._domainkey.bank.test", TestContext.Current.CancellationToken);
        Assert.Equal(KeyRecordState.Present, dns.KeyState("a._domainkey.bank.test"));   // unparsable modulus: present, not gone
        Assert.Equal(KeyRecordState.Revoked, dns.KeyState("r._domainkey.bank.test"));
        Assert.Equal(KeyRecordState.Missing, dns.KeyState("m._domainkey.bank.test"));
        Assert.Equal(KeyRecordState.Temp, dns.KeyState("t._domainkey.bank.test"));
        Assert.Equal(KeyRecordState.Unknown, dns.KeyState("u._domainkey.bank.test"));
        Assert.Equal(KeyRecordState.Missing, dns.KeyState("bad!._domainkey.bank.test"));
    }

    private sealed class Answers(Dictionary<string, TxtReply> replies) : ITxtTransport
    {
        public TxtReply Ask(string name, CancellationToken ct) => replies.GetValueOrDefault(name) ?? new TxtReply(TxtStatus.NxDomain, [], 300);
    }

    [Fact]
    public void Tags_FirstOccurrenceWinsAndWhitespaceIsRemoved()
    {
        var t = Tags.Parse(" v=1; A=rsa-sha256;\r\n\td=bank.test; b=AA AA\r\n BB; a=ignored; =x; novalue; s=");
        Assert.Equal("1", t["v"]);
        Assert.Equal("rsa-sha256", t["a"]);
        Assert.Equal("AAAABB", t["b"]);
        Assert.Equal("", t["s"]);
        Assert.False(t.ContainsKey("novalue"));
        Assert.Equal(Tags.MaxTags, Tags.Parse(string.Join(';', Enumerable.Range(0, 200).Select(i => $"t{i}=v"))).Count);
    }

    [Fact]
    public void HeaderOnly_FieldsAreSplitAndCanonicalized()
    {
        var header = Encoding.Latin1.GetBytes("From: A <a@bank.test>\nSubject:  hello\r\n\t world \r\nDKIM-Signature: v=1; b=AB\r\n CD; d=bank.test\r\n\r\nbody");
        var f = HeaderOnlyVerifier.Fields(header);
        Assert.Equal(["from", "subject", "dkim-signature"], f.Select(x => x.Name));
        Assert.Equal("Subject:  hello\r\n\t world \r\n", f[1].Raw);
        Assert.Equal("subject:hello world\r\n", HeaderOnlyVerifier.Canon(f[1].Raw, relaxed: true));
        Assert.Equal(f[1].Raw, HeaderOnlyVerifier.Canon(f[1].Raw, relaxed: false));
        Assert.Equal("DKIM-Signature: v=1; b=; d=bank.test\r\n", HeaderOnlyVerifier.WithoutB(f[2].Raw));
    }

    [Fact]
    public void SpamStatus_SpamAssassinAmavisAndFoldedTests()
    {
        var sa = ProviderVerdicts.ParseSpamStatus("Yes, score=11.7 required=5.0 tests=URIBL_DBL_PHISH,BAYES_99, HTML_MESSAGE autolearn=no version=4.0.1");
        Assert.NotNull(sa);
        Assert.True(sa.Spam);
        Assert.Equal(1170, sa.Score);
        Assert.Equal(500, sa.Required);
        Assert.Equal(["URIBL_DBL_PHISH", "BAYES_99", "HTML_MESSAGE"], sa.Tests);
        var amavis = ProviderVerdicts.ParseSpamStatus("No, score=-1.9 tagged_above=-999 required=6.31 tests=[BAYES_00=-1.9, DKIM_SIGNED=0.1] autolearn=ham");
        Assert.NotNull(amavis);
        Assert.False(amavis.Spam);
        Assert.Equal(["BAYES_00", "DKIM_SIGNED"], amavis.Tests);
        Assert.Null(ProviderVerdicts.ParseSpamStatus("Maybe, score=1"));
        Assert.Null(ProviderVerdicts.ParseSpamStatus("Yes, score=abc"));
        Assert.Null(ProviderVerdicts.ParseSpamStatus("Yes, tests=[unterminated"));
        Assert.Null(ProviderVerdicts.ParseSpamStatus("Yes, tests=" + string.Join(',', Enumerable.Range(0, ProviderVerdicts.MaxTests + 1).Select(i => $"T{i}"))));
    }

    [Fact]
    public void SpamdResult_AndPairs()
    {
        var r = ProviderVerdicts.ParseSpamdResult("default: False [11.70 / 9.00]; DBL_PHISH(5.00)[evil.test]; R_SPF_ALLOW(-0.20)[]");
        Assert.NotNull(r);
        Assert.False(r.Spam);
        Assert.Equal(1170, r.Score);
        Assert.Equal(900, r.Required);
        Assert.Equal(["DBL_PHISH", "R_SPF_ALLOW"], r.Tests);
        Assert.Null(ProviderVerdicts.ParseSpamdResult("default: False [11.70 / 9.00]; not a symbol"));
        var p = ProviderVerdicts.ParsePairs("CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:x.test;PTR:;CAT:NONE;DIR:INB;");
        Assert.NotNull(p);
        Assert.Equal("1", p["SCL"]);
        Assert.Equal("INB", p["DIR"]);
        Assert.Null(ProviderVerdicts.ParsePairs("SCL:1;SCL:9"));
        Assert.Null(ProviderVerdicts.ParsePairs("no-colon"));
        Assert.Equal(-150, ProviderVerdicts.Centi("-1.5"));
        Assert.Null(ProviderVerdicts.Centi("1e3"));
    }

    [Fact]
    public void SealerSigners_ShippedList()
    {
        var entry = Assert.Single(SealerSigners.Shipped["microsoft.com"]);
        Assert.Equal(new SignerEntry("onmicrosoft.com", Tenant: true), entry);
        Assert.Single(SealerSigners.Shipped);
    }
}
