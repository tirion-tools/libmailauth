using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using BcProperties = Org.BouncyCastle.Utilities.Properties;

namespace MailAuth;

/// <summary>
/// Validates each DKIM/ARC RSA public key record once with BouncyCastle's full default checks instead of once
/// per signature.
/// <para>
/// BouncyCastle 2.7.0 runs Miller-Rabin rounds in every <c>RsaKeyParameters</c> constructor and MimeKit 5 rebuilds
/// the key from the TXT record for every signature. So (1) every record the resolver hands to MimeKit for a
/// <c>_domainkey</c> name is checked here first: the modulus is parsed as MimeKit parses it (SubjectPublicKeyInfo,
/// else bare RSAPublicKey) and passed to <c>RsaKeyParameters.ValidateModulus</c> with the default iterations,
/// cached per record string; failing or unparsable records are removed from the answer. (2) Only around MimeKit's
/// verifier calls, on the calling thread, <see cref="Scope"/> sets BouncyCastle's thread property MaxMRTests=0 so
/// the per-signature re-validation of an already validated modulus is skipped. A process-wide MaxMRTests=0 is
/// never used: it verified a prime-modulus key.
/// </para>
/// One instance per <see cref="BrokeredDnsResolver"/> (one thread); not thread-safe.
/// </summary>
internal sealed class KeyValidation
{
    /// <summary>Bounds the per-record cache; on overflow it is cleared (records are re-validated, never trusted).</summary>
    public const int MaxCached = 4096;
    private readonly Dictionary<string, bool> _validated = new(StringComparer.Ordinal);

    public long Validations { get; private set; }

    /// <summary>The records MimeKit may see for <paramref name="name"/>: key records whose RSA modulus failed are dropped.</summary>
    public IReadOnlyList<string> Filter(string name, IReadOnlyList<string> records)
    {
        if (!name.Contains("._domainkey.", StringComparison.Ordinal)) return records;
        List<string>? kept = null;
        for (int i = 0; i < records.Count; i++)
        {
            bool ok = Usable(records[i]);
            if (!ok && kept == null) kept = records.Take(i).ToList();
            else if (ok) kept?.Add(records[i]);
        }
        return kept ?? records;
    }

    private bool Usable(string record)
    {
        if (_validated.TryGetValue(record, out bool ok)) return ok;
        ok = Validate(record);
        if (_validated.Count >= MaxCached) _validated.Clear();
        _validated[record] = ok;
        return ok;
    }

    private bool Validate(string record)
    {
        var tags = Tags.Parse(record);
        if (tags.TryGetValue("k", out var k) && !k.Equals("rsa", StringComparison.OrdinalIgnoreCase)) return true;   // ed25519: no modulus
        if (!tags.TryGetValue("p", out var p) || p.Length == 0) return true;   // missing or revoked: MimeKit decides
        byte[] der;
        try { der = Convert.FromBase64String(p); }
        catch (FormatException) { return false; }
        BigInteger? n = Modulus(der);
        if (n == null) return false;   // MimeKit could not build an RSA key from it either
        Validations++;
        // MimeKit calls the resolver from inside its verifier, i.e. inside Scope: lift the thread-scoped skip so this
        // one validation runs BouncyCastle's full default checks (validating under the skip accepted a prime modulus).
        string? saved = BcProperties.GetThreadProperty(BcProperties.RsaMaxMRTests);
        if (saved != null) BcProperties.RemoveThreadProperty(BcProperties.RsaMaxMRTests);
        try
        {
            RsaKeyParameters.ValidateModulus(n);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        finally
        {
            if (saved != null) BcProperties.SetThreadProperty(BcProperties.RsaMaxMRTests, saved);
        }
    }

    /// <summary>The two encodings MimeKit 5 accepts (DkimPublicKeyRecord.ParseRsaPublicKey), without building a key.</summary>
    private static BigInteger? Modulus(byte[] der)
    {
        Asn1Sequence seq;
        try { seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(der)); }
        catch (Exception) { return null; }
        try { return RsaPublicKeyStructure.GetInstance(SubjectPublicKeyInfo.GetInstance(seq).ParsePublicKey()).Modulus; }
        catch (Exception) { }
        try { return RsaPublicKeyStructure.GetInstance(seq).Modulus; }
        catch (Exception) { return null; }
    }

    /// <summary>Thread-scoped skip of BouncyCastle's per-signature re-validation; only records that passed Filter reach it.</summary>
    public readonly struct Scope : IDisposable
    {
        private readonly bool _set;

        public Scope(bool enable)
        {
            _set = enable;
            if (_set) BcProperties.SetThreadInt32(BcProperties.RsaMaxMRTests, 0);
        }

        public void Dispose()
        {
            if (_set) BcProperties.RemoveThreadProperty(BcProperties.RsaMaxMRTests);
        }
    }
}
