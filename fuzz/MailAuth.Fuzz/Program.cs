// Coverage-guided fuzz targets of MailAuth's parsers of untrusted input (fuzz/run.sh).
//   MailAuth.Fuzz                 libFuzzer target: run under libfuzzer-dotnet
//   MailAuth.Fuzz --seeds DIR     write the seed corpus of the selected target into DIR
// MAILAUTH_FUZZ_TARGET selects the target:
//   tags        the RFC 6376 tag-list parser (Tags.Parse) over the input as Latin-1 text.
//   headeronly  the header-only DKIM field split and canonicalization (HeaderOnlyVerifier.Fields, Canon, WithoutB)
//               over the input as a header block.
//   verdicts    the provider-verdict grammars: the first byte picks ParseSpamStatus, ParseSpamdResult or ParsePairs,
//               the rest is the field value.
// Every input must yield a result within the parser's limits; any exception escapes to SharpFuzz, which reports it to
// libFuzzer as a crash.
using System.Text;
using MailAuth;
using SharpFuzz;

string target = Environment.GetEnvironmentVariable("MAILAUTH_FUZZ_TARGET") ?? "";
(ReadOnlySpanAction Run, string[] Seeds) t = target switch
{
    "tags" => (Targets.Tags, Targets.TagSeeds),
    "headeronly" => (Targets.HeaderOnly, Targets.HeaderSeeds),
    "verdicts" => (Targets.Verdicts, Targets.VerdictSeeds),
    _ => throw new ArgumentException("MAILAUTH_FUZZ_TARGET must be tags, headeronly or verdicts"),
};
if (args is ["--seeds", var dir])
{
    Directory.CreateDirectory(dir);
    for (int i = 0; i < t.Seeds.Length; i++) File.WriteAllBytes(Path.Combine(dir, $"seed-{i:D2}"), Encoding.Latin1.GetBytes(t.Seeds[i]));
    return 0;
}
Fuzzer.LibFuzzer.Run(t.Run);
return 0;

internal static class Targets
{
    private static void Check(bool ok, string what)
    {
        if (!ok) throw new InvalidOperationException(what);
    }

    public static void Tags(ReadOnlySpan<byte> input)
    {
        var tags = MailAuth.Tags.Parse(Encoding.Latin1.GetString(input));
        Check(tags.Count <= MailAuth.Tags.MaxTags, "tag count over the limit");
        foreach (var (k, v) in tags)
            Check(k.Length > 0 && !v.Any(char.IsWhiteSpace), "empty name or whitespace in a value");
    }

    public static void HeaderOnly(ReadOnlySpan<byte> input)
    {
        foreach (var f in HeaderOnlyVerifier.Fields(input))
        {
            Check(f.Raw.EndsWith("\r\n", StringComparison.Ordinal), "field without its line end");
            // Verify canonicalizes only the DKIM-Signature field and fields named in h= (a tag value, so a name of
            // printable non-space characters); the invariants hold for those.
            if (f.Name.Length > 0 && f.Name.All(c => c is > ' ' and <= '~'))
            {
                string relaxed = HeaderOnlyVerifier.Canon(f.Raw, relaxed: true);
                Check(relaxed.EndsWith("\r\n", StringComparison.Ordinal) && relaxed.IndexOf("\r\n", StringComparison.Ordinal) == relaxed.Length - 2,
                      "relaxed canonical field not on one line");
                Check(HeaderOnlyVerifier.Canon(f.Raw, relaxed: false) == f.Raw, "simple canonicalization changed the field");
                Check(HeaderOnlyVerifier.WithoutB(f.Raw).Length <= f.Raw.Length, "b= removal grew the field");
            }
        }
    }

    public static void Verdicts(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0) return;
        string v = Encoding.Latin1.GetString(input[1..]);
        switch (input[0] % 3)
        {
            case 0:
                if (ProviderVerdicts.ParseSpamStatus(v) is { } s) Check(s.Tests.Count <= ProviderVerdicts.MaxTests, "tests over the limit");
                break;
            case 1:
                if (ProviderVerdicts.ParseSpamdResult(v) is { } r) Check(r.Tests.Count <= ProviderVerdicts.MaxTests, "symbols over the limit");
                break;
            default:
                if (ProviderVerdicts.ParsePairs(v) is { } p) Check(p.Count <= ProviderVerdicts.MaxPairs, "pairs over the limit");
                break;
        }
    }

    public static readonly string[] TagSeeds =
    [
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=bank.test; s=s1; h=from:subject; l=2; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=AAAA",
        "v=DKIM1; k=ed25519; p=dDXHk4TYhbuTmKBadx69wj7BrSa+/29GNgLZNWGromI=",
        "v=DMARC1; p=reject; sp=none; np=quarantine; t=y; adkim=r; aspf=s; pct=50; rua=mailto:a@b.test",
        "i=1; a=rsa-sha256; cv=none; d=list.test; s=arc; t=1700000000; b=AA\r\n\tAA",
    ];

    public static readonly string[] HeaderSeeds =
    [
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bank.test; s=s1;\r\n\th=from:subject; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n\tb=AAAA\r\nFrom: Bank <ceo@bank.test>\r\nSubject:  hello \r\n world\r\n\r\nbody",
        "From: a@x.test\nFrom: b@y.test\nList-Id: <news.list.test>\n\n",
        "X: \r\n\tcontinued\r\nno colon line\r\n",
    ];

    public static readonly string[] VerdictSeeds =
    [
        "\0Yes, score=11.7 required=5.0 tests=URIBL_DBL_PHISH,BAYES_99,\n\tHTML_MESSAGE autolearn=no version=4.0.1",
        "\0No, score=-1.9 tagged_above=-999 required=6.31 tests=[BAYES_00=-1.9, DKIM_SIGNED=0.1] autolearn=ham",
        "\u0001default: True [9.00 / 5.00]; DBL_PHISH(5.00)[evil.test]; R_SPF_ALLOW(-0.20)[]",
        "\u0002CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:x.test;PTR:;CAT:NONE;DIR:INB;",
        "\u0002BCL:7;ARA:1444111002;",
    ];
}
