namespace MailAuth;

// The TXT transport contract of BrokeredDnsResolver: the caller answers TXT lookups and persists final answers.

/// <summary>Status of one TXT answer from the transport.</summary>
public enum TxtStatus { Ok, NoData, NxDomain, Temp, Refused }

/// <summary>One TXT answer as the transport returned it; the resolver re-checks every limit.</summary>
public sealed record TxtReply(TxtStatus Status, IReadOnlyList<string> Records, uint Ttl);

/// <summary>
/// Answers one TXT lookup for the resolver, synchronously on the calling thread. A transport that cannot answer
/// in time (or is cancelled through <paramref name="ct"/>) returns <see cref="TxtStatus.Temp"/>.
/// </summary>
public interface ITxtTransport
{
    TxtReply Ask(string name, CancellationToken ct);
}

/// <summary>A persisted final answer: status <c>ok|nodata|nxdomain</c>, records as a JSON array of strings.</summary>
public sealed record TxtCacheRow(string Name, string Status, string RecordsJson, long ExpiresAt);
