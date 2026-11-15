using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using MimeKit;
using MimeKit.Cryptography;

namespace MailAuth;

/// <summary>How a verdict field is bound to the account's server.</summary>
[Flags]
internal enum VerdictForm
{
    None = 0,
    /// <summary>Written above the server's own stamp (amavisd-new, SpamAssassin's rewrite): only instances above the
    /// topmost Authentication-Results with the account's authserv-id; the topmost wins.</summary>
    Prepended = 1,
    /// <summary>Appended at the bottom (rspamd milter): only the bottom-most instance, inside one block of verdict fields
    /// with the bottom-most bind field whose value equals the queue id of the topmost Received by the server's host.</summary>
    AppendedBound = 2,
    /// <summary>The provider removes or renames incoming copies (Exchange Online): exactly one instance.</summary>
    Firewalled = 4,
}

/// <summary>
/// Per-account provider-verdict configuration: the server's authserv-id and Received host patterns, the form of each
/// field it writes, the bind field, and whether methods are read from the provider-sealed AAR or the anchor ARH.
/// </summary>
internal sealed record VerdictConfig(string[] Authserv, string[] ServerHosts, IReadOnlyDictionary<string, VerdictForm> Fields,
                                     string BindField, bool AarMethods, bool ArhMethods)
{
    public static readonly string[] KnownFields =
        ["x-spam-status", "x-spam-flag", "x-spam-score", "x-spamd-result", "x-spam", "x-rspamd-action",
         "x-ms-exchange-organization-scl", "x-forefront-antispam-report", "x-microsoft-antispam"];

    /// <summary>
    /// A stamping server known only by its authserv-id (exact or <c>*.suffix</c>; also its Received host pattern, as on
    /// both measured accounts): the SpamAssassin/amavis fields in the prepended form and
    /// the rspamd fields appended and bound by <c>X-Rspamd-Queue-Id</c>; methods from the anchor ARH. Each form is a
    /// binding a sender cannot forge, and verdicts only escalate, so a field is read in whichever of its forms holds
    /// on the message. The ≥ 90 % per-account form detection needs the account's history, which is not an input of
    /// the evaluation; the Microsoft 365 firewalled forms are not defaults.
    /// </summary>
    public static VerdictConfig ForStampingServer(string authservId) => new(
        [authservId], [authservId],
        new Dictionary<string, VerdictForm>(StringComparer.Ordinal)
        {
            ["x-spam-status"] = VerdictForm.Prepended | VerdictForm.AppendedBound,
            ["x-spam-flag"] = VerdictForm.Prepended,
            ["x-spam-score"] = VerdictForm.Prepended,
            ["x-spamd-result"] = VerdictForm.AppendedBound,
            ["x-spam"] = VerdictForm.AppendedBound,
            ["x-rspamd-action"] = VerdictForm.AppendedBound,
        },
        "x-rspamd-queue-id", AarMethods: false, ArhMethods: true);

    public static bool Match(string[] patterns, string? host)
    {
        foreach (var p in patterns)
            if (AuthPolicy.Matches(p, host)) return true;
        return false;
    }
}

/// <summary>
/// Strict, bounded extraction of provider spam/phishing verdicts bound to the account's receiving server
/// into a provider record.
/// Any limit violation makes that field unparsable; nothing is guessed. Verdicts only escalate.
/// </summary>
internal static partial class ProviderVerdicts
{
    public const int MaxHeaderFields = 1000;
    public const int MaxFieldBytes = 8192;
    public const int MaxTests = 256;
    public const int MaxRules = 8;
    public const int MaxMethods = 4;
    public const int MaxPairs = 64;

    public sealed record Field(int Index, string Name, string Value);

    /// <summary>MimeKit's parsed header list as unfolded fields; null over <see cref="MaxHeaderFields"/>.</summary>
    public static List<Field>? FromHeaders(HeaderList headers)
    {
        if (headers.Count > MaxHeaderFields) return null;
        var list = new List<Field>(headers.Count);
        foreach (var h in headers)
        {
            var raw = h.RawValue;
            string v = raw.Length > MaxFieldBytes * 2 ? new string('x', MaxFieldBytes + 1) : Unfold().Replace(Encoding.Latin1.GetString(raw), " ").Trim();
            list.Add(new Field(list.Count, h.Field.ToLowerInvariant(), v));
        }
        return list;
    }

    [GeneratedRegex(@"\r?\n[ \t]+", RegexOptions.CultureInvariant)]
    private static partial Regex Unfold();

    [GeneratedRegex(@"^\s*(?:\([^()]{0,256}\)\s*)?([A-Za-z0-9._-]{1,253})", RegexOptions.CultureInvariant)]
    private static partial Regex AuthservRx();

    [GeneratedRegex(@"\bby\s+([A-Za-z0-9._-]{1,253})", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ByRx();

    [GeneratedRegex(@"\bid\s+([A-Za-z0-9]{4,32})\b", RegexOptions.CultureInvariant)]
    private static partial Regex QidRx();

    public static string? AuthservId(string v)
    {
        var m = AuthservRx().Match(v);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant().TrimEnd('.') : null;
    }

    /// <summary>Topmost Authentication-Results whose authserv-id matches the account (the server's own stamp).</summary>
    public static int AnchorArh(List<Field> f, VerdictConfig cfg)
    {
        foreach (var x in f)
            if (x.Name == "authentication-results" && VerdictConfig.Match(cfg.Authserv, AuthservId(x.Value))) return x.Index;
        return -1;
    }

    /// <summary>Topmost Received written by one of the server's own hosts, and the queue id it records.</summary>
    public static (int Idx, string? Qid) AnchorReceived(List<Field> f, VerdictConfig cfg)
    {
        foreach (var x in f)
        {
            if (x.Name != "received" || x.Value.Length > MaxFieldBytes) continue;
            var b = ByRx().Match(x.Value);
            if (!b.Success || !VerdictConfig.Match(cfg.ServerHosts, b.Groups[1].Value)) continue;
            var q = QidRx().Match(x.Value, b.Index);
            return (x.Index, q.Success ? q.Groups[1].Value : null);
        }
        return (-1, null);
    }

    private sealed class Bound
    {
        public readonly Dictionary<string, (Field F, VerdictForm Form)> Fields = new(StringComparer.Ordinal);
        public readonly Ignored Ignored = new();
        public Provider.Types.Anchor Anchor = Provider.Types.Anchor.None;
    }

    private static Bound Bind(List<Field> f, VerdictConfig cfg)
    {
        var b = new Bound();
        int arh = AnchorArh(f, cfg);
        var (rcv, qid) = AnchorReceived(f, cfg);
        if (arh >= 0) b.Anchor = Provider.Types.Anchor.Arh;
        else if (rcv >= 0) b.Anchor = Provider.Types.Anchor.Received;
        var bind = f.LastOrDefault(x => x.Name == cfg.BindField);
        foreach (var name in VerdictConfig.KnownFields)
        {
            var inst = f.Where(x => x.Name == name).ToList();
            // Microsoft's renamed copies from another tenant are never read (counted for the record).
            if ((name.StartsWith("x-forefront", StringComparison.Ordinal) || name.StartsWith("x-microsoft", StringComparison.Ordinal))
                && f.Any(x => x.Name == name + "-untrusted"))
                b.Ignored.UntrustedCopy++;
            if (inst.Count == 0) continue;
            if (!cfg.Fields.TryGetValue(name, out var forms) || forms == VerdictForm.None)
            {
                // Not a field this account's server writes: every instance is someone else's.
                bool allBelow = arh >= 0 && inst.All(x => x.Index > arh);
                foreach (var _ in inst)
                    if (allBelow) b.Ignored.BelowAnchor++;
                    else b.Ignored.Unbound++;
                continue;
            }
            if (forms.HasFlag(VerdictForm.Prepended) && arh >= 0 && inst.FirstOrDefault(x => x.Index < arh) is { } above)
            {
                b.Ignored.BelowAnchor += (uint)inst.Count(x => x.Index > arh);
                b.Fields[name] = (above, VerdictForm.Prepended);
                continue;
            }
            var last = inst[^1];
            if (forms.HasFlag(VerdictForm.AppendedBound) && qid != null && bind != null
                && string.Equals(bind.Value.Trim(), qid, StringComparison.Ordinal) && SameBlock(f, last.Index, bind.Index, cfg))
            {
                b.Ignored.Unbound += (uint)(inst.Count - 1);
                b.Fields[name] = (last, VerdictForm.AppendedBound);
                continue;
            }
            if (forms.HasFlag(VerdictForm.Firewalled))
            {
                if (inst.Count == 1) b.Fields[name] = (inst[0], VerdictForm.Firewalled);
                else b.Ignored.Duplicate += (uint)inst.Count;
                continue;
            }
            if (forms.HasFlag(VerdictForm.Prepended))
            {
                if (arh < 0) b.Ignored.NoAnchor++;
                else b.Ignored.BelowAnchor += (uint)inst.Count(x => x.Index > arh);
            }
            else b.Ignored.Unbound += (uint)inst.Count;
        }
        return b;
    }

    /// <summary>Field-name prefixes of an appended verdict block (rspamd milter_headers routines, hostedemail's own tags).</summary>
    private static readonly string[] BlockPrefixes = ["x-rspamd-", "x-spam", "x-stat-signature", "x-rspam", "x-he-"];

    /// <summary>The verdict field and the bind field belong to one appended block: every field between them is a block
    /// field or the server's own appended Authentication-Results.</summary>
    public static bool SameBlock(List<Field> f, int a, int b, VerdictConfig cfg)
    {
        int lo = Math.Min(a, b), hi = Math.Max(a, b);
        for (int i = lo + 1; i < hi; i++)
        {
            if (BlockPrefixes.Any(p => f[i].Name.StartsWith(p, StringComparison.Ordinal))) continue;
            if (f[i].Name == "authentication-results" && VerdictConfig.Match(cfg.Authserv, AuthservId(f[i].Value))) continue;
            return false;
        }
        return true;
    }

    // ------------------------------------------------------------------ field grammars

    [GeneratedRegex(@"^-?\d{1,4}(?:\.\d{1,3})?$", RegexOptions.CultureInvariant)]
    private static partial Regex Num();

    [GeneratedRegex(@"^[A-Za-z0-9_]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex TestName();

    [GeneratedRegex(@"^(Yes|No)\b\s*(?:,\s*(.*))?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex SpamStatusRx();

    [GeneratedRegex("^[a-z_]{1,16}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyRx();

    [GeneratedRegex(@"^default:\s*(True|False)\s*\[\s*(-?\d{1,4}\.\d{1,3})\s*/\s*(-?\d{1,4}\.\d{1,3})\s*\]\s*(.*)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex SpamdRx();

    [GeneratedRegex(@"^([A-Za-z0-9_]{1,64})\(-?\d{1,4}(?:\.\d{1,3})?\)(?:\[.{0,1024}\])?$", RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex SymbolRx();

    [GeneratedRegex("^[A-Za-z]{1,12}$", RegexOptions.CultureInvariant)]
    private static partial Regex PairKeyRx();

    [GeneratedRegex("^[a-z0-9-]{1,32}$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenRx();

    [GeneratedRegex(@"^\d{3}$", RegexOptions.CultureInvariant)]
    private static partial Regex ReasonRx();

    [GeneratedRegex(@"^[A-Za-z0-9.-]{1,253}$", RegexOptions.CultureInvariant)]
    private static partial Regex ZoneRx();

    private static int? Centi(string s) =>
        Num().IsMatch(s) ? (int)Math.Round(double.Parse(s, CultureInfo.InvariantCulture) * 100) : null;

    public sealed record Status(bool Spam, int? Score, int? Required, List<string> Tests);

    /// <summary>X-Spam-Status in SpamAssassin, amavisd-new or rspamd form.</summary>
    public static Status? ParseSpamStatus(string v)
    {
        if (v.Length > MaxFieldBytes) return null;
        var m = SpamStatusRx().Match(v);
        if (!m.Success) return null;
        bool spam = m.Groups[1].Value.Equals("yes", StringComparison.OrdinalIgnoreCase);
        int? score = null, req = null;
        var tests = new List<string>();
        string rest = m.Groups[2].Success ? m.Groups[2].Value : "";
        int i = 0;
        while (i < rest.Length)
        {
            while (i < rest.Length && char.IsWhiteSpace(rest[i])) i++;
            if (i >= rest.Length) break;
            int eq = rest.IndexOf('=', i);
            if (eq < 0) return null;
            string key = rest[i..eq].Trim().ToLowerInvariant();
            if (!KeyRx().IsMatch(key)) return null;
            i = eq + 1;
            string val;
            if (i < rest.Length && rest[i] == '[')
            {
                int close = rest.IndexOf(']', i);
                if (close < 0) return null;
                val = rest[(i + 1)..close];
                i = close + 1;
            }
            else
            {
                int sp = i;
                while (sp < rest.Length && !char.IsWhiteSpace(rest[sp])) sp++;
                val = rest[i..sp];
                // SA folds the tests list after commas: "tests=A,B,\n\tC" unfolds to "A,B, C"
                if (key == "tests")
                    while (sp < rest.Length && val.EndsWith(','))
                    {
                        int s2 = sp;
                        while (s2 < rest.Length && char.IsWhiteSpace(rest[s2])) s2++;
                        int e2 = s2;
                        while (e2 < rest.Length && !char.IsWhiteSpace(rest[e2])) e2++;
                        if (s2 == e2 || rest.IndexOf('=', s2, e2 - s2) >= 0) break;
                        val += rest[s2..e2];
                        sp = e2;
                    }
                i = sp;
            }
            switch (key)
            {
                case "score": score = Centi(val); if (score == null) return null; break;
                case "required": req = Centi(val); if (req == null) return null; break;
                case "tests":
                    foreach (var t0 in val.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        string t = t0.Split('=')[0].Trim();
                        if (t.Length == 0 || t == "none") continue;
                        if (!TestName().IsMatch(t) || tests.Count >= MaxTests) return null;
                        tests.Add(t.ToUpperInvariant());
                    }
                    break;
                default: break;   // tagged_above, autolearn, version, hits: not used
            }
        }
        return new(spam, score, req, tests);
    }

    /// <summary>X-Spamd-Result: "default: False [11.70 / 9.00]; SYM(5.00)[opts]; SYM2(0.00)[]"</summary>
    public static Status? ParseSpamdResult(string v)
    {
        if (v.Length > MaxFieldBytes) return null;
        var m = SpamdRx().Match(v);
        if (!m.Success) return null;
        var tests = new List<string>();
        foreach (var part in m.Groups[4].Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var s = SymbolRx().Match(part);
            if (!s.Success || tests.Count >= MaxTests) return null;
            tests.Add(s.Groups[1].Value.ToUpperInvariant());
        }
        bool spam = m.Groups[1].Value.Equals("true", StringComparison.OrdinalIgnoreCase);
        return new(spam, Centi(m.Groups[2].Value), Centi(m.Groups[3].Value), tests);
    }

    /// <summary>"KEY:VALUE;KEY:VALUE;" (X-Forefront-Antispam-Report, X-Microsoft-Antispam); a repeated key is ambiguous.</summary>
    public static Dictionary<string, string>? ParsePairs(string v)
    {
        if (v.Length > MaxFieldBytes) return null;
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in v.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int c = part.IndexOf(':', StringComparison.Ordinal);
            if (c <= 0) return null;
            string k = part[..c].Trim();
            if (!PairKeyRx().IsMatch(k) || d.Count >= MaxPairs) return null;
            if (!d.TryAdd(k.ToUpperInvariant(), part[(c + 1)..].Trim())) return null;
        }
        return d;
    }

    private static readonly string[] SfvValues = ["NSPM", "SPM", "SKS", "SKA", "SKB", "SKI", "SKQ", "SKN", "BLK", "SFE", "SKU", "SKV"];
    private static readonly string[] CatValues = ["NONE", "BULK", "DIMP", "GIMP", "HPHSH", "HPHISH", "HSPM", "INTOS", "MALW", "OSPM", "PHSH", "SAP", "SPM", "SPOOF", "UIMP", "AMP", "FTBP"];

    private static int? Scl(string s) =>
        s.Length <= 2 && int.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int x) && x >= -1 && x <= 9 ? x : null;

    private static uint FormBit(VerdictForm f) => f switch
    {
        VerdictForm.Prepended => 1,
        VerdictForm.AppendedBound => 2,
        VerdictForm.Firewalled => 4,
        _ => 0,
    };

    private const uint FormAar = 8, FormArh = 16;

    /// <summary>
    /// The provider record. <paramref name="sealedAar"/> is the provider-sealed AAR the auth verdict came from, or null.
    /// No configuration: form none, spam unknown.
    /// </summary>
    public static Provider Extract(List<Field>? f, VerdictConfig? cfg, AuthenticationResults? sealedAar, IReadOnlySet<string> phishRules, IReadOnlySet<string> malwareRules)
    {
        var o = new Provider { Spam = Provider.Types.Spam.Unknown, Anchor = Provider.Types.Anchor.None };
        if (cfg == null) return o;
        if (f == null) { o.Error = "header over field limit"; return o; }
        var b = Bind(f, cfg);
        o.Anchor = b.Anchor;
        o.Ignored = b.Ignored;
        uint forms = 0;
        var engines = new SortedSet<string>(StringComparer.Ordinal);
        var rules = new SortedSet<string>(StringComparer.Ordinal);
        bool? spam = null;
        bool phish = false, malware = false, high = false, bulk = false;
        int? score = null, required = null, scl = null;
        void Says(bool s) => spam = spam == true || s;
        void TestsToFlags(List<string> tests)
        {
            foreach (var t in tests)
            {
                if (phishRules.Contains(t)) { phish = true; if (rules.Count < MaxRules) rules.Add(t); }
                if (malwareRules.Contains(t)) { malware = true; if (rules.Count < MaxRules) rules.Add(t); }
            }
        }

        if (b.Fields.TryGetValue("x-spam-status", out var xs))
        {
            var st = ParseSpamStatus(xs.F.Value);
            if (st == null) b.Ignored.Unparsable++;
            else
            {
                forms |= FormBit(xs.Form);
                engines.Add(xs.F.Value.Contains("tagged_above=", StringComparison.Ordinal) ? "amavis" : st.Tests.Count > 0 || st.Required != null ? "spamassassin" : "rspamd");
                Says(st.Spam);
                score = st.Score ?? score;
                required = st.Required ?? required;
                if (st.Spam && st.Score != null && st.Required is int r && r > 0 && st.Score >= 2 * r) high = true;
                TestsToFlags(st.Tests);
            }
        }
        foreach (var name in (string[])["x-spam-flag", "x-spam"])
        {
            if (!b.Fields.TryGetValue(name, out var xf)) continue;
            string v = xf.F.Value.Trim();
            if (v.Equals("YES", StringComparison.OrdinalIgnoreCase)) { Says(true); forms |= FormBit(xf.Form); }
            else if (v.Equals("NO", StringComparison.OrdinalIgnoreCase)) { Says(false); forms |= FormBit(xf.Form); }
            else b.Ignored.Unparsable++;
        }
        if (b.Fields.TryGetValue("x-spam-score", out var xss))
        {
            var c = Centi(xss.F.Value.Trim());
            if (c == null) b.Ignored.Unparsable++;
            else { score ??= c; forms |= FormBit(xss.Form); }
        }
        if (b.Fields.TryGetValue("x-spamd-result", out var xr))
        {
            var st = ParseSpamdResult(xr.F.Value);
            if (st == null) b.Ignored.Unparsable++;
            else
            {
                forms |= FormBit(xr.Form);
                engines.Add("rspamd");
                Says(st.Spam || (st.Score is int s && st.Required is int r && s >= r));
                score ??= st.Score;
                required ??= st.Required;
                TestsToFlags(st.Tests);
            }
        }
        if (b.Fields.TryGetValue("x-rspamd-action", out var xa))
        {
            string v = xa.F.Value.Trim().ToLowerInvariant();
            if (v is "no action" or "greylist") { Says(false); forms |= FormBit(xa.Form); }
            else if (v is "add header" or "rewrite subject" or "soft reject") { Says(true); forms |= FormBit(xa.Form); }
            else if (v == "reject") { Says(true); high = true; forms |= FormBit(xa.Form); }
            else b.Ignored.Unparsable++;
            if (v.Length <= 16) o.Action = v;
        }
        if (b.Fields.TryGetValue("x-ms-exchange-organization-scl", out var xscl))
        {
            var s = Scl(xscl.F.Value.Trim());
            if (s == null) b.Ignored.Unparsable++;
            else
            {
                forms |= FormBit(xscl.Form);
                engines.Add("eop");
                scl = s;
                Says(s >= 5);
                if (s >= 9) high = true;
            }
        }
        if (b.Fields.TryGetValue("x-forefront-antispam-report", out var xfr))
        {
            var p = ParsePairs(xfr.F.Value);
            string? dir = p?.GetValueOrDefault("DIR");
            int? s = p != null && p.TryGetValue("SCL", out var sv) ? Scl(sv) : null;
            string? sfv = p?.GetValueOrDefault("SFV"), cat = p?.GetValueOrDefault("CAT");
            if (p == null || (p.ContainsKey("SCL") && s == null) || (sfv != null && !SfvValues.Contains(sfv)) || (cat != null && !CatValues.Contains(cat)))
                b.Ignored.Unparsable++;
            else if (dir != "INB") b.Ignored.UntrustedCopy++;   // outbound or internal report of another hop
            else
            {
                forms |= FormBit(xfr.Form);
                engines.Add("eop");
                if (s != null) { scl ??= s; if (s >= 5) Says(true); else if (sfv is "NSPM") Says(false); if (s >= 9) high = true; }
                if (sfv != null) o.Sfv = sfv;
                if (cat != null) o.Cat = cat;
                if (sfv is "SPM" or "SKS" or "SKB" or "BLK") Says(true);
                if (cat is "PHSH" or "HPHSH" or "HPHISH") { phish = true; Says(true); }
                if (cat is "HPHSH" or "HPHISH" or "HSPM") high = true;
                if (cat == "MALW") { malware = true; Says(true); }
                if (cat == "BULK") bulk = true;
            }
        }
        if (b.Fields.TryGetValue("x-microsoft-antispam", out var xma))
        {
            var p = ParsePairs(xma.F.Value);
            if (p == null) b.Ignored.Unparsable++;
            else if (p.TryGetValue("BCL", out var bv))
            {
                if (bv.Length == 1 && bv[0] is >= '0' and <= '9')
                {
                    o.Bcl = bv[0] - '0';
                    forms |= FormBit(xma.Form);
                    if (o.Bcl >= 7) bulk = true;
                }
                else b.Ignored.Unparsable++;
            }
        }

        // Methods inside the trusted results: the provider-sealed AAR, or the anchor ARH of a stamping server.
        AuthenticationResults? ar = null;
        uint arForm = 0;
        if (cfg.AarMethods && sealedAar != null) { ar = sealedAar; arForm = FormAar; }
        else if (cfg.ArhMethods)
        {
            int idx = AnchorArh(f, cfg);
            if (idx >= 0 && AuthenticationResults.TryParse(Encoding.Latin1.GetBytes(f[idx].Value), out var parsed)) { ar = parsed; arForm = FormArh; }
        }
        if (ar != null)
        {
            foreach (var m in ar.Results)
            {
                string meth = (m.Method ?? "").ToLowerInvariant(), res = (m.Result ?? "").ToLowerInvariant();
                if (meth is "spf" or "dkim" or "dmarc" or "arc" or "auth" or "" || o.Methods.Count >= MaxMethods) continue;
                if (!TokenRx().IsMatch(meth) || !TokenRx().IsMatch(res)) { b.Ignored.Unparsable++; continue; }
                var e = new Method { Method_ = meth, Result = res };
                if (meth == "compauth")
                {
                    string reason = m.Reason ?? "";
                    o.Compauth = new CompAuth { Result = res, Reason = ReasonRx().IsMatch(reason) ? reason : "" };
                }
                else
                {
                    var zone = m.Properties.FirstOrDefault(p => string.Equals(p.Property, "zone", StringComparison.OrdinalIgnoreCase))?.Value;
                    if (zone != null && ZoneRx().IsMatch(zone) && zone.Length <= 64) e.Zone = zone.ToLowerInvariant();
                }
                o.Methods.Add(e);
            }
            if (o.Methods.Count > 0) forms |= arForm;
        }

        o.Form = forms;
        o.Engine = engines.FirstOrDefault() switch
        {
            "amavis" => Provider.Types.Engine.Amavis,
            "eop" => Provider.Types.Engine.Eop,
            "rspamd" => Provider.Types.Engine.Rspamd,
            "spamassassin" => Provider.Types.Engine.Spamassassin,
            _ => Provider.Types.Engine.Unspecified,
        };
        o.Spam = spam == null ? Provider.Types.Spam.Unknown : spam == true ? Provider.Types.Spam.Yes : Provider.Types.Spam.No;
        o.Phish = phish;
        o.Malware = malware;
        o.High = high;
        o.Bulk = bulk;
        if (score is int sc) o.ScoreCenti = sc;
        if (required is int rq) o.RequiredCenti = rq;
        if (scl is int sl) o.Scl = sl;
        o.Rules.AddRange(rules);
        return o;
    }
}
