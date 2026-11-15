using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Text.Json;
using MailAuth;

namespace MailAuth.Tests;

/// <summary>
/// The synthetic authentication fixtures dkim-aot, arc-sealer-dkim and provider-verdicts
/// (each with its own keys and DNS zone) and their recorded expected results, in
/// tests/fixtures/&lt;set&gt;/{fixtures.tar.gz, zone.json, expected.json}.
/// </summary>
internal sealed class SignalsFixtureSet
{
    public string Name { get; }
    public Dictionary<string, byte[]> Fixtures { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, byte[]> Verdicts { get; } = new(StringComparer.Ordinal);
    public JsonElement Zone { get; }
    public JsonElement Expected { get; }

    private static readonly Dictionary<string, SignalsFixtureSet> Cache = new(StringComparer.Ordinal);

    public static string Root([CallerFilePath] string here = "") => Path.Combine(Path.GetDirectoryName(here)!, "Fixtures", "signals");

    public static SignalsFixtureSet Load(string name)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(name, out var set)) Cache[name] = set = new SignalsFixtureSet(name);
            return set;
        }
    }

    private SignalsFixtureSet(string name)
    {
        Name = name;
        string dir = Path.Combine(Root(), name);
        using (var gz = new GZipStream(File.OpenRead(Path.Combine(dir, "fixtures.tar.gz")), CompressionMode.Decompress))
        using (var tar = new TarReader(gz))
            while (tar.GetNextEntry() is { } e)
            {
                if (e.DataStream == null) continue;
                using var ms = new MemoryStream();
                e.DataStream.CopyTo(ms);
                string file = Path.GetFileNameWithoutExtension(e.Name);
                (e.Name.StartsWith("verdicts/", StringComparison.Ordinal) ? Verdicts : Fixtures)[file] = ms.ToArray();
            }
        Zone = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(dir, "zone.json"))).RootElement.GetProperty("names");
        Expected = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(dir, "expected.json"))).RootElement;
    }

    /// <summary>A fixture account configuration (configs.json / verdict-configs.json shape) as an <see cref="AuthPolicy"/>.</summary>
    public static AuthPolicy Policy(JsonElement cfg)
    {
        static string[] Arr(JsonElement o, string k) =>
            o.TryGetProperty(k, out var a) && a.ValueKind == JsonValueKind.Array ? a.EnumerateArray().Select(x => x.GetString()!.ToLowerInvariant()).ToArray() : [];
        var signers = new Dictionary<string, SignerEntry[]>(StringComparer.Ordinal);
        if (cfg.TryGetProperty("sealer_signers", out var ss))
            foreach (var p in ss.EnumerateObject())
                signers[p.Name] = p.Value.EnumerateArray()
                    .Where(e => e.TryGetProperty("ship", out var s) && s.GetBoolean())
                    .Select(e => new SignerEntry(e.GetProperty("signer").GetString()!, e.GetProperty("kind").GetString() == "tenant")).ToArray();
        VerdictConfig? verdicts = null;
        if (cfg.TryGetProperty("verdicts", out var v))
        {
            var fields = new Dictionary<string, VerdictForm>(StringComparer.Ordinal);
            foreach (var f in v.GetProperty("fields").EnumerateObject())
                fields[f.Name] = f.Value.GetString() switch
                {
                    "prepended" => VerdictForm.Prepended,
                    "appended_bound" => VerdictForm.AppendedBound,
                    "firewalled" => VerdictForm.Firewalled,
                    var x => throw new InvalidDataException("form " + x),
                };
            verdicts = new VerdictConfig(Arr(v, "authserv"), Arr(v, "server_hosts"), fields,
                v.TryGetProperty("bind", out var b) ? b.GetString()! : "x-rspamd-queue-id",
                v.TryGetProperty("aar_methods", out var aar) && aar.GetBoolean(), v.TryGetProperty("arh_methods", out var arh) && arh.GetBoolean());
        }
        string? id = cfg.TryGetProperty("authserv_id", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null;
        return new AuthPolicy(id, Arr(cfg, "provider_sealers"), Arr(cfg, "forwarder_sealers"), signers, verdicts);
    }

    /// <summary>The header block of a raw message, up to and including the empty line.</summary>
    public static byte[] Header(byte[] raw)
    {
        int e = raw.AsSpan().IndexOf("\r\n\r\n"u8);
        return e < 0 ? raw : raw[..(e + 4)];
    }
}

/// <summary>
/// The fixture DNS zone as a TXT transport would answer it: CNAMEs
/// followed, servfail/delay behaviours give temp, answers over the limits or with non-printable bytes are refused.
/// </summary>
internal sealed class ZoneTransport(JsonElement names) : ITxtTransport
{
    public int Asks { get; private set; }
    public List<string> Asked { get; } = [];

    public TxtReply Ask(string name, CancellationToken ct)
    {
        Asks++;
        Asked.Add(name);
        string n = name;
        for (int hops = 0; hops < 8; hops++)
        {
            if (!names.TryGetProperty(n, out var rec)) return new TxtReply(TxtStatus.NxDomain, [], 300);
            string beh = rec.TryGetProperty("behavior", out var b) ? b.GetString()! : "";
            if (beh.StartsWith("delay", StringComparison.Ordinal) || beh == "servfail") return new TxtReply(TxtStatus.Temp, [], 0);
            if (rec.TryGetProperty("cname", out var c)) { n = c.GetString()!; continue; }
            if (!rec.TryGetProperty("txt", out var txt) || txt.GetArrayLength() == 0) return new TxtReply(TxtStatus.NoData, [], 300);
            var recs = txt.EnumerateArray().Select(t => string.Concat(t.EnumerateArray().Select(x => x.GetString()))).ToArray();
            if (recs.Length > 16 || recs.Any(x => x.Length > 2048) || recs.Sum(x => x.Length) > 4096 || recs.Any(x => x.Any(ch => ch < 0x20 || ch > 0x7e)))
                return new TxtReply(TxtStatus.Refused, [], 0);
            return new TxtReply(TxtStatus.Ok, recs, 300);
        }
        return new TxtReply(TxtStatus.Temp, [], 0);
    }
}
