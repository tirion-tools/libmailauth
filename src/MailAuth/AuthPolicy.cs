namespace MailAuth;

/// <summary>A sealer-signer pairing: <c>exact</c> (organizational domain equals Signer) or <c>tenant</c>.</summary>
public sealed record SignerEntry(string Signer, bool Tenant);

/// <summary>
/// The trust inputs of one account for <see cref="AuthEvaluator"/>.
/// <list type="bullet">
/// <item><see cref="AuthservId"/>: the receiving server's authserv-id, exact or a <c>*.suffix</c> pattern.</item>
/// <item><see cref="ProviderSealers"/>: ARC sealer domains of the account's own provider; when set, the verdict comes only
///   from an ARC-Authentication-Results that provider sealed in a validating chain, never from plain Authentication-Results.</item>
/// <item><see cref="ForwarderSealers"/>: sealers the user marked as trusted forwarders.</item>
/// <item><see cref="SealerSigners"/>: the sealer-signer list keyed by sealer organizational domain.</item>
/// <item><see cref="Verdicts"/>: which provider verdict fields are read and how they are bound; null reads none.</item>
/// </list>
/// </summary>
public sealed record AuthPolicy(string? AuthservId, string[] ProviderSealers, string[] ForwarderSealers,
    IReadOnlyDictionary<string, SignerEntry[]> SealerSigners, VerdictConfig? Verdicts)
{
    /// <summary>An authserv-id or host against an exact name or a <c>*.suffix</c> pattern.</summary>
    public static bool Matches(string? pattern, string? value)
    {
        if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(value)) return false;
        value = value.ToLowerInvariant().TrimEnd('.');
        return pattern.StartsWith("*.", StringComparison.Ordinal)
            ? value.Length > pattern.Length - 1 && value.EndsWith(pattern[1..], StringComparison.Ordinal)
            : value == pattern;
    }
}
