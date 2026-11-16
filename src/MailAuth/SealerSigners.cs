using System.Text.Json;

namespace MailAuth;

/// <summary>
/// The shipped ARC sealer to DKIM signer list (<c>Data/sealer-signers.json</c>, embedded as
/// <see cref="ResourceName"/>), keyed by sealer organizational domain; see <see cref="AuthPolicy.SealerSigners"/>.
/// </summary>
internal static class SealerSigners
{
    public const string ResourceName = "MailAuth.Data.sealer-signers.json";

    private static readonly Lazy<IReadOnlyDictionary<string, SignerEntry[]>> ShippedList = new(() =>
    {
        using var s = typeof(SealerSigners).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("missing embedded resource " + ResourceName);
        return Load(s);
    }, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>The shipped list; loaded once, immutable and shared.</summary>
    public static IReadOnlyDictionary<string, SignerEntry[]> Shipped => ShippedList.Value;

    /// <summary>A list in the shipped format: <c>{"sealers": {"&lt;sealer&gt;": [{"signer": "…", "kind": "exact|tenant"}]}}</c>.</summary>
    public static IReadOnlyDictionary<string, SignerEntry[]> Load(Stream json)
    {
        var signers = new Dictionary<string, SignerEntry[]>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(json);
        foreach (var p in doc.RootElement.GetProperty("sealers").EnumerateObject())
            signers[p.Name.ToLowerInvariant()] = p.Value.EnumerateArray()
                .Select(e => new SignerEntry(e.GetProperty("signer").GetString()!.ToLowerInvariant(), e.GetProperty("kind").GetString() == "tenant"))
                .ToArray();
        return signers;
    }
}
