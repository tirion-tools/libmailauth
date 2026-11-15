using System.Text.Json;
using MimeKit.Cryptography;

namespace MailAuth;

/// <summary>The state of a DKIM key record as last answered (see <see cref="BrokeredDnsResolver.KeyState"/>).</summary>
internal enum KeyRecordState { Unknown, Missing, Revoked, Present, Temp }

/// <summary>
/// MimeKit 5's <see cref="IDnsResolver"/> over a caller-supplied TXT transport.
/// Lookup order: this resolver's memory, then the persisted rows
/// given at construction (merged into memory), then <see cref="ITxtTransport"/>.
/// Final answers (ok, nodata, nxdomain) are kept in memory and handed to the persist callback; temp and refused
/// answers, and replies outside the transport limits, are a temporary failure held in memory for
/// <see cref="TempTtl"/> seconds and never persisted. Key records pass <see cref="KeyValidation"/> before MimeKit
/// sees them. One instance per thread; not thread-safe.
/// </summary>
internal sealed class BrokeredDnsResolver : IDnsResolver
{
    // The transport limits; a reply outside them is a temporary failure.
    public const int MaxName = 253, MaxLabel = 63, MaxRecords = 16, MaxRecordBytes = 2048, MaxTotalBytes = 4096;
    /// <summary>Seconds a temporary failure is remembered within a sync (memory only).</summary>
    public const int TempTtl = 30;
    /// <summary>Clamp of the answer TTL for the cache, in seconds.</summary>
    public const uint MinTtl = 300, MaxTtl = 86400;
    /// <summary>Bound of the in-memory cache; on overflow it is cleared (answers are asked again, never invented).</summary>
    public const int MaxMemory = 65536;

    private static readonly string[] SpecialUseTop = ["localhost", "local", "invalid", "onion", "arpa", "internal", "alt", "home", "lan"];

    private readonly ITxtTransport _transport;
    private readonly Action<TxtCacheRow> _persist;
    private readonly Dictionary<string, Entry> _mem = new(StringComparer.Ordinal);

    public KeyValidation Keys { get; } = new();
    /// <summary>Cancellation of the current evaluation; MimeKit's own token is <c>None</c> on the synchronous paths.</summary>
    public CancellationToken Token { get; set; }
    public Func<long> Clock { get; set; } = static () => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    /// <summary>Calls to the transport (all time) and temporary failures returned during the current pass.</summary>
    public long Asked { get; private set; }
    public int TempFailures { get; set; }

    internal readonly record struct Entry(DnsQueryStatus Status, string[] Records, long Expires, bool Final);

    public BrokeredDnsResolver(IEnumerable<TxtCacheRow> cached, ITxtTransport transport, Action<TxtCacheRow> persist)
    {
        _transport = transport;
        _persist = persist;
        foreach (var row in cached)
            if (FromRow(row) is { } e && TryName(row.Name, out var n)) _mem[n] = e;
    }

    /// <summary>A stored row as a cache entry, or null for a malformed row (then the name is asked again).</summary>
    internal static Entry? FromRow(TxtCacheRow row)
    {
        DnsQueryStatus status;
        switch (row.Status)
        {
            case "ok": status = DnsQueryStatus.Success; break;
            case "nodata": status = DnsQueryStatus.Success; break;
            case "nxdomain": status = DnsQueryStatus.NonExistentDomain; break;
            default: return null;
        }
        var recs = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(row.RecordsJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return null;
            foreach (var x in doc.RootElement.EnumerateArray())
            {
                if (x.ValueKind != JsonValueKind.String) return null;
                recs.Add(x.GetString()!);
            }
        }
        catch (JsonException) { return null; }
        if (!WithinLimits(recs) || (row.Status != "ok" && recs.Count > 0)) return null;
        return new Entry(status, [.. recs], row.ExpiresAt, true);
    }

    /// <summary>
    /// The names the resolver asks for, lower-cased: <c>&lt;selector&gt;._domainkey.&lt;domain&gt;</c>
    /// (domain of at least 2 labels) or <c>_dmarc.&lt;domain&gt;</c>; bytes <c>[a-z0-9-._]</c>, at most 253 bytes, labels
    /// 1-63, no other underscore label, no numeric or special-use top label. Any other name is answered
    /// non-existent locally, never asked: a name the transport refuses must not turn a failure into a temporary one.
    /// </summary>
    internal static bool TryName(string domain, out string name)
    {
        name = domain.TrimEnd('.').ToLowerInvariant();
        if (name.Length is 0 or > MaxName) return false;
        foreach (char c in name)
            if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_')) return false;
        var labels = name.Split('.');
        foreach (var l in labels)
            if (l.Length is 0 or > MaxLabel) return false;
        string top = labels[^1];
        if (top.All(char.IsAsciiDigit) || SpecialUseTop.Contains(top) || top.Contains('_', StringComparison.Ordinal)) return false;
        int dk = Array.IndexOf(labels, "_domainkey");
        int domainStart;
        if (labels[0] == "_dmarc") domainStart = 1;
        else if (dk >= 1) domainStart = dk + 1;
        else return false;
        int domainLabels = labels.Length - domainStart;
        if (domainLabels < (labels[0] == "_dmarc" ? 1 : 2)) return false;
        for (int i = domainStart; i < labels.Length; i++)
            if (labels[i].Contains('_', StringComparison.Ordinal)) return false;
        return true;
    }

    private static bool WithinLimits(IReadOnlyList<string> recs)
    {
        if (recs.Count > MaxRecords) return false;
        int total = 0;
        foreach (var r in recs)
        {
            if (r.Length > MaxRecordBytes) return false;
            total += r.Length;
            foreach (char c in r)
                if (c is < (char)0x20 or > (char)0x7E) return false;
        }
        return total <= MaxTotalBytes;
    }

    /// <summary>The cache entry for one transport reply (limits re-checked; temp, refused and violations are not final).</summary>
    internal static Entry Map(TxtReply? reply, long now)
    {
        if (reply == null) return new Entry(DnsQueryStatus.TemporaryFailure, [], now + TempTtl, false);
        long expires = now + Math.Clamp(reply.Ttl, MinTtl, MaxTtl);
        var records = reply.Records ?? [];
        switch (reply.Status)
        {
            case TxtStatus.Ok:
                if (records.Count == 0) return new Entry(DnsQueryStatus.Success, [], expires, true);
                if (!WithinLimits(records)) return new Entry(DnsQueryStatus.TemporaryFailure, [], now + TempTtl, false);
                return new Entry(DnsQueryStatus.Success, [.. records], expires, true);
            case TxtStatus.NoData: return new Entry(DnsQueryStatus.Success, [], expires, true);
            case TxtStatus.NxDomain: return new Entry(DnsQueryStatus.NonExistentDomain, [], expires, true);
            default: return new Entry(DnsQueryStatus.TemporaryFailure, [], now + TempTtl, false);
        }
    }

    private DnsTxtResponse Response(string name, Entry e)
    {
        if (e.Status == DnsQueryStatus.TemporaryFailure) TempFailures++;
        return e.Status == DnsQueryStatus.Success ? new DnsTxtResponse(Keys.Filter(name, e.Records)) : new DnsTxtResponse(e.Status);
    }

    public DnsTxtResponse QueryTxt(string domain, CancellationToken cancellationToken = default)
    {
        if (!TryName(domain, out var name)) return new DnsTxtResponse(DnsQueryStatus.NonExistentDomain);
        long now = Clock();
        if (_mem.TryGetValue(name, out var hit) && hit.Expires > now) return Response(name, hit);
        var ct = cancellationToken.CanBeCanceled ? cancellationToken : Token;
        TxtReply? reply;
        if (ct.IsCancellationRequested) reply = null;
        else
        {
            Asked++;
            reply = _transport.Ask(name, ct);
        }
        var e = Map(reply, now);
        if (_mem.Count >= MaxMemory) _mem.Clear();
        _mem[name] = e;
        if (e.Final)
        {
            string status = e.Status == DnsQueryStatus.NonExistentDomain ? "nxdomain" : e.Records.Length == 0 ? "nodata" : "ok";
            _persist(new TxtCacheRow(name, status, JsonSerializer.Serialize(e.Records, RecordsJson.Default.StringArray), e.Expires));
        }
        return Response(name, e);
    }

    /// <summary>
    /// What the last answer for a key name said, from the raw records (before <see cref="KeyValidation"/> drops
    /// failing keys, so a prime modulus is a present key with a bad signature, not a missing key). A name never asked
    /// is Unknown; a name the transport would refuse is Missing (it was answered non-existent locally).
    /// </summary>
    public KeyRecordState KeyState(string domain)
    {
        if (!TryName(domain, out var name)) return KeyRecordState.Missing;
        if (!_mem.TryGetValue(name, out var e)) return KeyRecordState.Unknown;
        if (e.Status == DnsQueryStatus.TemporaryFailure) return KeyRecordState.Temp;
        if (e.Status != DnsQueryStatus.Success) return KeyRecordState.Missing;
        bool anyP = false;
        foreach (var r in e.Records)
            if (Tags.Parse(r).TryGetValue("p", out var p))
            {
                if (p.Length > 0) return KeyRecordState.Present;
                anyP = true;
            }
        return anyP ? KeyRecordState.Revoked : KeyRecordState.Missing;
    }

    public Task<DnsTxtResponse> QueryTxtAsync(string domain, CancellationToken cancellationToken = default) =>
        Task.FromResult(QueryTxt(domain, cancellationToken));
}
