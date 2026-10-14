using System;
using System.Runtime.InteropServices;
using System.Text;

namespace GeregeSystems.EidMongolia.Pades
{
    /// <summary>Go-гийн malloc-оор олгосон санах ой; <c>eid_free</c>-ээр нэг л удаа чөлөөлнө.</summary>
    internal sealed class NativeBuffer : SafeHandle
    {
        public NativeBuffer() : base(IntPtr.Zero, ownsHandle: true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            NativeMethods.eid_free(handle);
            return true;
        }

        public byte[] ToArray(UIntPtr length)
        {
            if (IsInvalid) return Array.Empty<byte>();
            ulong n = length.ToUInt64();
            if (n > int.MaxValue) throw new EidPadesException("INTERNAL", "native output exceeds 2 GiB");
            var bytes = new byte[(int)n];
            bool added = false;
            try
            {
                DangerousAddRef(ref added);
                Marshal.Copy(DangerousGetHandle(), bytes, 0, bytes.Length);
            }
            finally
            {
                if (added) DangerousRelease();
            }
            return bytes;
        }

        /// <summary>NUL-terminated UTF-8.</summary>
        public string ToUtf8String()
        {
            if (IsInvalid) return "";
            bool added = false;
            try
            {
                DangerousAddRef(ref added);
                IntPtr p = DangerousGetHandle();
                int len = 0;
                while (Marshal.ReadByte(p, len) != 0) len++;
                var bytes = new byte[len];
                Marshal.Copy(p, bytes, 0, len);
                return Encoding.UTF8.GetString(bytes);
            }
            finally
            {
                if (added) DangerousRelease();
            }
        }
    }

    internal static class NativeMethods
    {
        private const string Lib = "eidpades";

        // Бүх функц: 0 = амжилт; ≠0 = алдаа, *err = {"code","message"} JSON (UTF-8, NUL-terminated).
        // Гаралтын буфер бүрийг eid_free-ээр чөлөөлнө (NativeBuffer).

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int eid_pades_prepare(
            byte[] pdf, UIntPtr pdfLen, byte[] optsJson,
            out NativeBuffer outJson, out UIntPtr outLen, out NativeBuffer err);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int eid_pades_complete(
            byte[] state, UIntPtr stateLen, byte[] sig, UIntPtr sigLen, byte[] optsJson,
            out NativeBuffer outPdf, out UIntPtr outLen, out NativeBuffer outMetaJson, out NativeBuffer err);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int eid_pades_verify(
            byte[] pdf, UIntPtr pdfLen, byte[] optsJson,
            out NativeBuffer outJson, out UIntPtr outLen, out NativeBuffer err);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern NativeBuffer eid_pades_version();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void eid_free(IntPtr p);

        /// <summary>UTF-8 + NUL терминатор (C <c>const char*</c>).</summary>
        internal static byte[] CString(string s)
        {
            var b = Encoding.UTF8.GetBytes(s);
            Array.Resize(ref b, b.Length + 1);
            return b;
        }
    }
}
