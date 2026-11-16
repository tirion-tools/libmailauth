using System.Text;
using System.Text.Json;
using MimeKit;
using Xunit;

namespace MailAuth.Tests;

/// <summary><see cref="AuthEvaluator"/> against the fixture sets and their recorded verdicts.</summary>
public sealed class EvaluatorTests(ITestOutputHelper output)
{
    private static readonly string[] Configs = ["selfhosted", "provider", "list"];
    private static readonly string[] FinalStatuses = ["ok", "nodata", "nxdomain"];
    private static readonly ParserOptions Parser = new() { MaxHeaderLength = 256 * 1024 };

    /// <summary>Largest message the tests verify in full; bigger ones are verified from the header block.</summary>
    internal const int FullLimit = 256 * 1024;

    /// <summary>Registrable domain for the fixtures: the last two labels (every fixture domain is under a one-label suffix).</summary>
    internal static string? Registrable(string host)
    {
        var labels = host.TrimEnd('.').Split('.');
        return labels.Length < 2 || labels.Any(l => l.Length == 0) ? null : labels[^2] + "." + labels[^1];
    }

    internal static readonly AuthPolicy Local = new(null, [], [], SealerSigners.Shipped, null);
    internal static readonly AuthPolicy Stamping = new("mx.provider.test", [], [], SealerSigners.Shipped, VerdictConfig.ForStampingServer("mx.provider.test"));

    internal static MimeMessage Parse(byte[] raw) => MimeMessage.Load(Parser, new MemoryStream(raw, false));

    internal static AuthOutcome Evaluate(AuthEvaluator ev, byte[] raw, AuthPolicy policy, bool full)
    {
        var input = full ? raw : FixtureSet.Header(raw);
        var msg = Parse(input);
        return full ? ev.Evaluate(msg, input, policy) : ev.EvaluateHeaderOnly(msg, input, raw.LongLength, policy);
    }

    private static AuthOutcome Run(FixtureSet set, byte[] raw, AuthPolicy policy, bool full = true)
    {
        var ev = new AuthEvaluator(new BrokeredDnsResolver([], new ZoneTransport(set.Zone), _ => { }), Registrable);
        return Evaluate(ev, raw, policy, full);
    }

    private static AuthOutcome Fixture(string set, string name, AuthPolicy policy, bool full = true)
    {
        var s = FixtureSet.Load(set);
        return Run(s, s.Fixtures[name], policy, full);
    }

    private static string Recorded(string verdict) => verdict == "verified_forwarded" ? "verified" : verdict;

    private (int Checked, List<string> Mismatches) FullVerdicts(string setName)
    {
        var set = FixtureSet.Load(setName);
        var configs = set.Expected.GetProperty("configs");
        var mism = new List<string>();
        int n = 0;
        foreach (var fx in set.Expected.GetProperty("full").EnumerateObject())
            foreach (var c in Configs)
            {
                if (!configs.TryGetProperty(c, out var cfg)) continue;
                var o = Run(set, set.Fixtures[fx.Name], FixtureSet.Policy(cfg));
                n++;
                string want = fx.Value.GetProperty(c).GetString()!;
                if (Recorded(o.Verdict) != want) mism.Add($"{setName}/{fx.Name} [{c}]: {o.Verdict} ({o.Source}: {o.Reason}), recorded {want}");
            }
        output.WriteLine($"{setName}: {n - mism.Count}/{n} verdicts match");
        foreach (var m in mism) output.WriteLine("  MISMATCH " + m);
        return (n, mism);
    }

    [Fact]
    public void DkimAotFixtures_MatchTheRecordedVerdicts()
    {
        var (n, mism) = FullVerdicts("dkim-aot");
        Assert.Equal(56 * 3, n);
        Assert.Empty(mism);
    }

    [Fact]
    public void ArcSealerDkimFixtures_MatchTheRecordedVerdicts()
    {
        var (n, mism) = FullVerdicts("arc-sealer-dkim");
        Assert.Equal(106 * 3, n);
        Assert.Empty(mism);
    }

    [Fact]
    public void ProviderVerdictFixtures_MatchTheRecordedAuthVerdicts()
    {
        var (n, mism) = FullVerdicts("provider-verdicts");
        Assert.Equal(106 * 3, n);
        Assert.Empty(mism);
    }

    [Theory]
    [InlineData("arc-sealer-dkim")]
    [InlineData("provider-verdicts")]
    public void HeaderOnly_MatchesTheRecordedHeaderOnlyVerdicts(string setName)
    {
        var set = FixtureSet.Load(setName);
        var policy = FixtureSet.Policy(set.Expected.GetProperty("configs").GetProperty("selfhosted"));
        var mism = new List<string>();
        int n = 0;
        foreach (var fx in set.Expected.GetProperty("header_only").EnumerateObject())
        {
            var o = Run(set, set.Fixtures[fx.Name], policy, full: false);
            n++;
            string want = fx.Value.GetString()!;
            string got = o.PendingOpen ? "pending" : Recorded(o.Verdict);
            if (got != want) mism.Add($"{fx.Name}: {got} ({o.Reason}), recorded {want}");
        }
        output.WriteLine($"{setName} header-only: {n - mism.Count}/{n} match");
        foreach (var m in mism) output.WriteLine("  " + m);
        Assert.Equal(106, n);
        Assert.Empty(mism);
    }

    [Fact]
    public void ProviderVerdictFixtures_BindAsRecorded()
    {
        var set = FixtureSet.Load("provider-verdicts");
        var configs = set.Expected.GetProperty("verdict_configs");
        var mism = new List<string>();
        int n = 0, bound = 0;
        foreach (var fx in set.Expected.GetProperty("verdicts").EnumerateObject())
            foreach (var c in fx.Value.EnumerateObject())
            {
                var policy = FixtureSet.Policy(configs.GetProperty(c.Name));
                var raw = set.Verdicts[fx.Name];
                var o = Run(set, raw, policy);
                n++;
                string wantAuth = c.Value.GetProperty("auth").GetString()!;
                if (Recorded(o.Verdict) != wantAuth) mism.Add($"{fx.Name} [{c.Name}]: auth {o.Verdict}, recorded {wantAuth}");
                var want = c.Value.GetProperty("provider");
                if (policy.Verdicts == null || want.ValueKind != JsonValueKind.Object) continue;
                bound++;
                var fields = ProviderVerdicts.FromHeaders(Parse(raw).Headers);
                var b = fields == null ? null : ProviderVerdicts.Bind(fields, policy.Verdicts);
                string anchor = (b?.Anchor ?? VerdictAnchor.None).ToString().ToLowerInvariant();
                if (want.TryGetProperty("anchor", out var wa) && wa.GetString() != anchor) mism.Add($"{fx.Name} [{c.Name}]: anchor {anchor}, recorded {wa.GetString()}");
                // Below-anchor, no-anchor, unbound and duplicate counts come from the binding alone (the record adds
                // unparsable fields and other hops' reports).
                if (b != null && want.TryGetProperty("ignored", out var ig))
                {
                    string got = $"{b.Ignored.BelowAnchor},{b.Ignored.NoAnchor},{b.Ignored.Unbound},{b.Ignored.Duplicate}";
                    string w = $"{ig.GetProperty("below_anchor").GetInt32()},{ig.GetProperty("no_anchor").GetInt32()},{ig.GetProperty("unbound").GetInt32()},{ig.GetProperty("duplicate").GetInt32()}";
                    if (got != w) mism.Add($"{fx.Name} [{c.Name}]: ignored {got}, recorded {w}");
                }
            }
        output.WriteLine($"provider verdicts: {n} fixture x config auth verdicts, {bound} bindings; {mism.Count} mismatches");
        foreach (var m in mism) output.WriteLine("  " + m);
        Assert.True(bound > 0);
        Assert.Empty(mism);
    }

    // ------------------------------------------------------------------ named cases

    [Fact]
    public void ForgedArh_IsNeverTrustedWithoutTheServersStamp()
    {
        // A header claiming the account's authserv-id on mail without the server's own stamp: local verification fails it.
        var forged = Fixture("provider-verdicts", "arh_missing_forged_sameid", Local);
        Assert.Equal("local", forged.Source);
        Assert.Equal("failed", forged.Verdict);
        Assert.True(forged.UnsignedDmarcFail);
        // A forged same-id header below the real one is ignored (topmost rule).
        Assert.Equal("trusted_arh", Fixture("provider-verdicts", "arh_attacker_sameid_below", Stamping).Source);
        // A sealing provider's plain Authentication-Results are never trusted, even with its authserv-id on top.
        var sealing = new AuthPolicy("mx.google.com", ["google.com"], [], SealerSigners.Shipped, null);
        Assert.Equal("local", Fixture("provider-verdicts", "arh_attacker_sameid_above", sealing).Source);
    }

    [Fact]
    public void TwoFrom_IsFailed()
    {
        Assert.Equal("failed", Fixture("provider-verdicts", "ho_two_from", Local).Verdict);
        Assert.Equal("failed", Fixture("provider-verdicts", "from_added_not_oversigned", Local).Verdict);
        Assert.Equal("failed", Fixture("provider-verdicts", "ho_two_from", Local, full: false).Verdict);
    }

    [Fact]
    public void LengthTagNotCoveringTheBody_DoesNotCount()
    {
        Assert.NotEqual("verified", Fixture("provider-verdicts", "dkim_l_appended", Local).Verdict);
        Assert.Equal("failed", Fixture("provider-verdicts", "ho_l_appended", Local, full: false).Verdict);
    }

    [Fact]
    public void PrimeModulusKey_IsRejected()
    {
        var o = Fixture("provider-verdicts", "dkim_key_prime_modulus", Local);
        Assert.NotEqual("verified", o.Verdict);
        Assert.DoesNotContain(o.Dkim, d => d.Result == "pass");
        Assert.Equal("failed", Fixture("provider-verdicts", "ho_key_prime_modulus", Local, full: false).Verdict);
    }

    [Fact]
    public void AttackerSealedArc_NeverUpgrades()
    {
        var set = FixtureSet.Load("provider-verdicts");
        foreach (var c in Configs)
            Assert.Equal("failed", Run(set, set.Fixtures["arc_attacker_sealed"], FixtureSet.Policy(set.Expected.GetProperty("configs").GetProperty(c))).Verdict);
    }

    [Fact]
    public void ServfailOnTheKey_IsNoneTemporaryNeverFailed()
    {
        var full = Fixture("provider-verdicts", "dns_servfail", Local);
        Assert.Equal("none", full.Verdict);
        Assert.True(full.Temporary);
        var ho = Fixture("provider-verdicts", "ho_dns_servfail", Local, full: false);
        Assert.Equal("none", ho.Verdict);
        Assert.True(ho.Temporary);
    }

    [Theory]
    [InlineData("dkim_key_missing", true)]
    [InlineData("dkim_key_revoked", true)]
    [InlineData("dkim_body_modified", false)]   // a present key with a bad signature is not gone
    public void KeyGone_IsSetOnlyWhenEveryKeyIsMissingOrRevoked(string fixture, bool gone)
    {
        var o = Fixture("provider-verdicts", fixture, Local);
        Assert.Equal("failed", o.Verdict);
        Assert.Equal(gone, o.KeyGone);
    }

    [Fact]
    public void SigningEvidence_IsAnAlignedPass()
    {
        Assert.True(Fixture("provider-verdicts", "dkim_rsa_relaxed", Local).SigningEvidence);
        Assert.False(Fixture("provider-verdicts", "unsigned_bank_spoof", Local).SigningEvidence);
    }

    [Fact]
    public void BadSelector_IsNotAskedAndCannotTurnFailedIntoTemporary()
    {
        var zone = new ZoneTransport(FixtureSet.Load("provider-verdicts").Zone);
        var ev = new AuthEvaluator(new BrokeredDnsResolver([], zone, _ => { }), Registrable);
        var raw = Encoding.ASCII.GetBytes(
            "From: ceo@bank.test\r\nTo: a@example.com\r\nSubject: x\r\n" +
            "DKIM-Signature: v=1; a=rsa-sha256; d=bank.test; s=bad!sel; h=from; bh=AAAA; b=AAAA\r\n\r\nbody\r\n");
        var o = Evaluate(ev, raw, Local, full: true);
        Assert.DoesNotContain(zone.Asked, x => x.Contains('!', StringComparison.Ordinal));
        Assert.False(o.Temporary);
    }

    [Fact]
    public void HostileInput_NeverThrows()
    {
        var set = FixtureSet.Load("provider-verdicts");
        var ev = new AuthEvaluator(new BrokeredDnsResolver([], new ZoneTransport(set.Zone), _ => { }), Registrable);
        var rng = new Random(7);
        int evaluated = 0;
        foreach (var raw in set.Fixtures.Values.Take(40))
            for (int k = 0; k < 5; k++)
            {
                var b = (byte[])raw.Clone();
                for (int j = 0; j < 20; j++) b[rng.Next(b.Length)] = (byte)rng.Next(256);
                MimeMessage msg;
                try { msg = Parse(b); }
                catch (FormatException) { continue; }   // MimeKit: no parsable header block
                ev.Evaluate(msg, b, Stamping);
                ev.EvaluateHeaderOnly(msg, FixtureSet.Header(b), b.LongLength + FullLimit, Stamping);
                ProviderVerdicts.Bind(ProviderVerdicts.FromHeaders(msg.Headers) ?? [], Stamping.Verdicts!);
                evaluated++;
            }
        Assert.True(evaluated > 100);
    }

    // ------------------------------------------------------------------ cache

    [Fact]
    public void Cache_WarmPassAsksNothingAndTemporaryAnswersAreNeverPersisted()
    {
        var set = FixtureSet.Load("provider-verdicts");
        void Pass(AuthEvaluator ev)
        {
            foreach (var raw in set.Fixtures.Values)
            {
                try { Evaluate(ev, raw, Local, raw.Length <= FullLimit); }
                catch (FormatException) { }
            }
        }
        var zone = new ZoneTransport(set.Zone);
        var persisted = new List<TxtCacheRow>();
        var ev1 = new AuthEvaluator(new BrokeredDnsResolver([], zone, persisted.Add), Registrable);
        Pass(ev1);
        int cold = zone.Asks;
        Assert.True(cold > 0);
        var probe = new ZoneTransport(set.Zone);
        var temp = zone.Asked.Where(n => probe.Ask(n, default).Status is TxtStatus.Temp or TxtStatus.Refused).ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(temp);
        Assert.DoesNotContain(persisted, r => temp.Contains(r.Name));
        Assert.All(persisted, r => Assert.Contains(r.Status, FinalStatuses));
        Assert.Equal(persisted.Count, persisted.Select(r => r.Name).Distinct().Count());

        // Warm pass on the same resolver: nothing asked (temporary failures are held for TempTtl in memory only).
        int before = zone.Asks;
        Pass(ev1);
        Assert.Equal(before, zone.Asks);

        // A new resolver from the persisted rows: only the temporary names are asked again.
        var zone2 = new ZoneTransport(set.Zone);
        var persisted2 = new List<TxtCacheRow>();
        Pass(new AuthEvaluator(new BrokeredDnsResolver(persisted, zone2, persisted2.Add), Registrable));
        Assert.Subset(temp, zone2.Asked.ToHashSet(StringComparer.Ordinal));
        Assert.Empty(persisted2);
        output.WriteLine($"cache: cold pass {cold} asks, {persisted.Count} rows persisted; warm pass 0 asks; restart pass {zone2.Asks} asks (temporary names only: {temp.Count})");
    }
}
