using System.Runtime.CompilerServices;
using GeregeSystems.EidMongolia.Qr;

// «Миний QR» (GeregeSystems.EidMongolia.Qr) 0.17.0-оос core багц GeregeSystems.EidMongolia-д. Pades 0.16.0-ийн эсрэг
// compile хийсэн хэрэглэгч дахин compile-гүйгээр ажиллахын тулд нийтийн төрөл бүрийг core руу дамжуулна (нэр, namespace,
// гишүүд 0.16.0-тэй ижил — CI-ийн compat job шалгана; docs/release-0.17.0.md).
[assembly: TypeForwardedTo(typeof(EidQr))]
[assembly: TypeForwardedTo(typeof(EidQrClient))]
[assembly: TypeForwardedTo(typeof(EidQrOptions))]
[assembly: TypeForwardedTo(typeof(EidQrException))]
[assembly: TypeForwardedTo(typeof(EidQrErrorCodes))]
[assembly: TypeForwardedTo(typeof(QrStartRequest))]
[assembly: TypeForwardedTo(typeof(QrSession))]
[assembly: TypeForwardedTo(typeof(QrSigner))]
[assembly: TypeForwardedTo(typeof(QrResult))]
[assembly: TypeForwardedTo(typeof(QrExpect))]
[assembly: TypeForwardedTo(typeof(QrTrust))]
[assembly: TypeForwardedTo(typeof(QrCheck))]
