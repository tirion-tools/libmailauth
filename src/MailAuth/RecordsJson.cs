using System.Text.Json.Serialization;

namespace MailAuth;

/// <summary>Source-generated (NativeAOT-safe) JSON for the records of a persisted TXT answer (<see cref="TxtCacheRow"/>).</summary>
[JsonSerializable(typeof(string[]))]
internal sealed partial class RecordsJson : JsonSerializerContext;
