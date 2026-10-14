using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace GeregeSystems.EidMongolia.Pades
{
    /// <summary>
    /// eID client-side PAdES. PDF клиентээс гарахгүй: <see cref="Prepare"/> → DTBS-ийг утас/токеноор зуруулах →
    /// <see cref="CompleteAsync"/> → гарын үсэгтэй PDF. Thread-safe (цөм глобал төлөвгүй).
    /// </summary>
    public static class EidPades
    {
        private static readonly JsonSerializerOptions Json = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        /// <summary>Цөмийн хувилбар (Go module + commit).</summary>
        public static string Version()
        {
            using var v = Call(() => NativeMethods.eid_pades_version());
            return v.ToUtf8String();
        }

        /// <summary>PDF-д гарын үсгийн placeholder бэлдэж, зурах DTBS-ийг буцаана. Сүлжээ ашиглахгүй.</summary>
        public static PreparedDocument Prepare(byte[] pdf, PrepareOptions options)
        {
            if (pdf is null) throw new ArgumentNullException(nameof(pdf));
            if (options is null) throw new ArgumentNullException(nameof(options));
            if (options.SignerCert is null || options.SignerCert.Length == 0)
                throw new ArgumentException("SignerCert is required", nameof(options));

            var opts = NativeMethods.CString(JsonSerializer.Serialize(options, Json));
            var rc = Call((out NativeBuffer o, out UIntPtr l, out NativeBuffer e) =>
                NativeMethods.eid_pades_prepare(pdf, (UIntPtr)pdf.Length, opts, out o, out l, out e), out var res);
            using (res.Out) using (res.Err)
            {
                ThrowIfFailed(rc, res.Err);
                var bytes = res.Out.ToArray(res.Len);
                return JsonSerializer.Deserialize<PreparedDocument>(bytes, Json)
                       ?? throw new EidPadesException("INTERNAL", "empty prepare result");
            }
        }

        /// <summary>
        /// Гарын үсгийг суулгана: DTBS дээрх гарын үсгийг шалгах → RFC 3161 TS → CMS → DSS (OCSP/CRL) → өөрийгөө шалгах.
        /// Сүлжээ (TSA, OCSP) ашигладаг тул thread pool дээр ажиллана. <paramref name="cancellationToken"/> нь
        /// эхлэхээс өмнө л шалгагдана: эхэлсэн native дуудлагыг тасалж болохгүй (цөмийн timeout дуусгана).
        /// </summary>
        /// <param name="state"><see cref="PreparedDocument.State"/>.</param>
        /// <param name="signature">r||s (ECDSA), DER ECDSA эсвэл PKCS#1 v1.5 (RSA) — цөм өөрөө танина.</param>
        /// <param name="options">TSA, итгэлийн тулгуур; <c>null</c> = анхдагч.</param>
        /// <param name="cancellationToken">Зөвхөн эхлэхээс өмнө шалгагдана.</param>
        public static Task<Completed> CompleteAsync(byte[] state, byte[] signature, CompleteOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            if (state is null) throw new ArgumentNullException(nameof(state));
            if (signature is null) throw new ArgumentNullException(nameof(signature));
            var opts = NativeMethods.CString(JsonSerializer.Serialize(options ?? new CompleteOptions(), Json));
            return Task.Run(() =>
            {
                NativeBuffer? meta = null;
                try
                {
                    var rc = Call((out NativeBuffer o, out UIntPtr l, out NativeBuffer e) =>
                    {
                        var r = NativeMethods.eid_pades_complete(state, (UIntPtr)state.Length,
                            signature, (UIntPtr)signature.Length, opts, out o, out l, out var m, out e);
                        meta = m;
                        return r;
                    }, out var res);
                    using (res.Out) using (res.Err)
                    {
                        ThrowIfFailed(rc, res.Err);
                        var pdf = res.Out.ToArray(res.Len);
                        var m = JsonSerializer.Deserialize<Completed>(meta?.ToUtf8String() ?? "", Json)
                                ?? throw new EidPadesException("INTERNAL", "empty complete metadata");
                        return m with { Pdf = pdf };
                    }
                }
                catch (JsonException e)
                {
                    throw new EidPadesException("INTERNAL", "invalid complete metadata", e);
                }
                finally
                {
                    meta?.Dispose();
                }
            }, cancellationToken);
        }

        /// <summary>PDF-ийн гарын үсгүүдийг шалгана (сүлжээгүй).</summary>
        public static VerifyReport Verify(byte[] pdf, VerifyOptions? options = null)
        {
            if (pdf is null) throw new ArgumentNullException(nameof(pdf));
            var opts = NativeMethods.CString(JsonSerializer.Serialize(options ?? new VerifyOptions(), Json));
            var rc = Call((out NativeBuffer o, out UIntPtr l, out NativeBuffer e) =>
                NativeMethods.eid_pades_verify(pdf, (UIntPtr)pdf.Length, opts, out o, out l, out e), out var res);
            using (res.Out) using (res.Err)
            {
                ThrowIfFailed(rc, res.Err);
                return new VerifyReport(System.Text.Encoding.UTF8.GetString(res.Out.ToArray(res.Len)));
            }
        }

        // ---- internals ----

        private struct NativeResult
        {
            public NativeBuffer Out;
            public UIntPtr Len;
            public NativeBuffer Err;
        }

        private delegate int NativeCall(out NativeBuffer o, out UIntPtr len, out NativeBuffer err);

        private static int Call(NativeCall f, out NativeResult res)
        {
            res = default;
            try
            {
                int rc = f(out var o, out var l, out var e);
                res.Out = o;
                res.Len = l;
                res.Err = e;
                return rc;
            }
            catch (Exception e) when (e is DllNotFoundException || e is EntryPointNotFoundException || e is BadImageFormatException)
            {
                throw new EidPadesException("NATIVE_UNAVAILABLE", "eidpades native library could not be loaded", e);
            }
        }

        private static T Call<T>(Func<T> f)
        {
            try { return f(); }
            catch (Exception e) when (e is DllNotFoundException || e is EntryPointNotFoundException || e is BadImageFormatException)
            {
                throw new EidPadesException("NATIVE_UNAVAILABLE", "eidpades native library could not be loaded", e);
            }
        }

        private static void ThrowIfFailed(int rc, NativeBuffer err)
        {
            if (rc == 0) return;
            string code = "UNKNOWN", message = "native call failed (" + rc + ")";
            var json = err.ToUtf8String();
            if (json.Length > 0)
            {
                try
                {
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String)
                        code = c.GetString() ?? code;
                    if (doc.RootElement.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                        message = m.GetString() ?? message;
                }
                catch (JsonException)
                {
                    message = json;
                }
            }
            throw new EidPadesException(code, message);
        }
    }
}
