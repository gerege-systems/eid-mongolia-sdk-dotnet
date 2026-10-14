# eid-mongolia-sdk-dotnet

**eID Mongolia** client-side PAdES — Windows (.NET) wrapper. PDF баримт eID сервер рүү **хэзээ ч явахгүй**: баримтыг
клиент дээр бэлдэж (`Prepare`), зөвхөн 32 байт хэш (DTBS)-ийг иргэний утас / USB токеноор зуруулаад, гарын үсгийг
клиент дээр PDF-д суулгана (`Complete`). Цөм нь Go (`eid-mongolia-sdk-go/pades`), Windows-д `eidpades.dll` болж
P/Invoke-оор дуудагдана.

Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.
