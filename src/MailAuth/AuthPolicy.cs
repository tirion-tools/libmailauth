namespace MailAuth;

/// <summary>A shipped sealer-signer pairing: <c>exact</c> (organizational domain equals Signer) or <c>tenant</c>.</summary>
internal sealed record SignerEntry(string Signer, bool Tenant);

/// <summary>
/// The trust inputs of the authentication rule for one account.
/// <list type="bullet">
/// <item><see cref="AuthservId"/>: the receiving server's authserv-id, exact or a <c>*.suffix</c> pattern.</item>
/// <item><see cref="ProviderSealers"/>: ARC sealer domains of the account's own provider; when set, the verdict comes only
///   from an ARC-Authentication-Results that provider sealed in a validating chain, never from plain Authentication-Results.</item>
/// <item><see cref="ForwarderSealers"/>: sealers the user marked as trusted forwarders.</item>
/// <item><see cref="SealerSigners"/>: the shipped sealer-signer list keyed by sealer organizational domain.</item>
/// <item><see cref="Verdicts"/>: which provider verdict fields are read and how they are bound; null reads none.</item>
/// </list>
/// </summary>
internal sealed record AuthPolicy(string? AuthservId, string[] ProviderSealers, string[] ForwarderSealers,
    IReadOnlyDictionary<string, SignerEntry[]> SealerSigners, VerdictConfig? Verdicts)
{
    /// <summary>
    /// Provider sealers that ship: Gmail (google.com) and Microsoft 365 (microsoft.com)
    /// sealing inbound mail is unconfirmed until the live header capture, and "an unconfirmed provider ships with
    /// local verification". Both are therefore empty; per-account detection of the sealing form needs
    /// the account's message history, which is not an input here.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string[]> ShippedProviderSealers = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["gmail"] = [],       // google.com: unconfirmed, local verification
        ["microsoft"] = [],   // microsoft.com: unconfirmed, local verification
    };

    /// <summary>
    /// The production policy of an account. <c>imap</c> with an authserv-id: trusted Authentication-Results
    /// (topmost-header rule) and provider verdicts bound to that server (<see cref="VerdictConfig.ForStampingServer"/>).
    /// <c>gmail</c>/<c>microsoft</c>: their plain Authentication-Results are never trusted (sealing providers, §3.1)
    /// and their sealed results only once shipped, so local verification; Gmail exposes no header verdict and
    /// the Microsoft 365 firewalled forms are not shipped as defaults before the live capture. Trusted
    /// forwarders are a user setting that is not an input yet, so none.
    /// </summary>
    public static AuthPolicy For(AccountAuth account, IReadOnlyDictionary<string, SignerEntry[]> signers)
    {
        string provider = account.Provider ?? "";
        string? id = NormalizeId(account.AuthservId);
        if (provider == "imap")
            return new AuthPolicy(id, [], [], signers, id == null ? null : VerdictConfig.ForStampingServer(id));
        string[] sealers = ShippedProviderSealers.GetValueOrDefault(provider) ?? [];
        return new AuthPolicy(sealers.Length > 0 ? id : null, sealers, [], signers, null);
    }

    private static string? NormalizeId(string? id)
    {
        id = id?.Trim().TrimEnd('.').ToLowerInvariant();
        return string.IsNullOrEmpty(id) || id.Length > 253 ? null : id;
    }

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
