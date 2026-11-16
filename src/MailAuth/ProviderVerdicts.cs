using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using MimeKit;

namespace MailAuth;

/// <summary>How a verdict field is bound to the account's server.</summary>
[Flags]
public enum VerdictForm
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

/// <summary>What bound the verdict fields: the server's Authentication-Results, its Received, or nothing.</summary>
public enum VerdictAnchor { None, Arh, Received }

/// <summary>Instances of verdict fields that were not read, by reason.</summary>
public sealed class IgnoredCounts
{
    /// <summary>Below the server's anchor Authentication-Results (another hop wrote them).</summary>
    public uint BelowAnchor { get; set; }
    /// <summary>A prepended field with no anchor Authentication-Results on the message.</summary>
    public uint NoAnchor { get; set; }
    /// <summary>Not bound to the server (wrong position, queue id or block).</summary>
    public uint Unbound { get; set; }
    /// <summary>A firewalled field present more than once.</summary>
    public uint Duplicate { get; set; }
    /// <summary>Outside the field's grammar or limits.</summary>
    public uint Unparsable { get; set; }
    /// <summary>A renamed copy from another tenant, or the report of another hop.</summary>
    public uint UntrustedCopy { get; set; }
}

/// <summary>
/// Per-account provider-verdict configuration: the server's authserv-id and Received host patterns, the form of each
/// field it writes, the bind field, and whether methods are read from the provider-sealed AAR or the anchor ARH.
/// </summary>
public sealed record VerdictConfig(string[] Authserv, string[] ServerHosts, IReadOnlyDictionary<string, VerdictForm> Fields,
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
    /// on the message. Per-account form detection needs the account's history, which is not an input here; the
    /// Microsoft 365 firewalled forms are not defaults.
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
/// Strict, bounded binding of provider spam/phishing verdict fields to the account's receiving server
/// and the grammars of those fields.
/// Any limit violation makes that field unparsable; nothing is guessed.
/// </summary>
public static partial class ProviderVerdicts
{
    public const int MaxHeaderFields = 1000;
    public const int MaxFieldBytes = 8192;
    public const int MaxTests = 256;
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

    /// <summary>The verdict fields bound to the account's server, the anchor that bound them and what was not read.</summary>
    public sealed class BoundVerdicts
    {
        public Dictionary<string, (Field F, VerdictForm Form)> Fields { get; } = new(StringComparer.Ordinal);
        public IgnoredCounts Ignored { get; } = new();
        public VerdictAnchor Anchor { get; set; } = VerdictAnchor.None;
    }

    /// <summary>Binds every known verdict field of <paramref name="f"/> to the server of <paramref name="cfg"/> by its form.</summary>
    public static BoundVerdicts Bind(List<Field> f, VerdictConfig cfg)
    {
        var b = new BoundVerdicts();
        int arh = AnchorArh(f, cfg);
        var (rcv, qid) = AnchorReceived(f, cfg);
        if (arh >= 0) b.Anchor = VerdictAnchor.Arh;
        else if (rcv >= 0) b.Anchor = VerdictAnchor.Received;
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

    /// <summary>A score such as <c>-1.5</c> or <c>11.70</c> in hundredths, or null outside the grammar.</summary>
    public static int? Centi(string s) =>
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
}
