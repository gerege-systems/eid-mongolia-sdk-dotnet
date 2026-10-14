using System;
using System.IO;
using System.Security.Cryptography;

namespace GeregeSystems.EidMongolia.Pades.Tests;

internal static class Fixtures
{
    public static readonly string Golden = Path.Combine(AppContext.BaseDirectory, "testdata", "golden");

    public static byte[] Read(params string[] rel) => File.ReadAllBytes(Path.Combine(Golden, Path.Combine(rel)));

    public static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
}
