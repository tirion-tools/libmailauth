namespace MailAuth;

/// <summary>RFC 6376 §3.2 tag lists (DKIM-Signature, ARC-Seal, DKIM key and DMARC records), whitespace removed from values.</summary>
internal static class Tags
{
    /// <summary>Tags beyond this count are ignored (a real record has fewer than 20).</summary>
    public const int MaxTags = 64;

    /// <summary>First occurrence of each tag wins; names compare case-insensitively.</summary>
    public static Dictionary<string, string> Parse(string value)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in value.Split(';'))
        {
            if (d.Count >= MaxTags) break;
            int eq = part.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0) continue;
            string k = part[..eq].Trim();
            if (k.Length == 0) continue;
            var v = part.AsSpan(eq + 1);
            var sb = new System.Text.StringBuilder(v.Length);
            foreach (char c in v)
                if (!char.IsWhiteSpace(c)) sb.Append(c);
            d.TryAdd(k, sb.ToString());
        }
        return d;
    }
}
