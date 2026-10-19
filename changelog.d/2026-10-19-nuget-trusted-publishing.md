- **Release: nuget.org-д нийтэлнэ (Trusted Publishing).**
  - Юу: `release.yml` — `v*` tag дээр `GeregeSystems.EidMongolia.Pades` багцыг GitHub Release + GitHub Packages-аас гадна
    nuget.org-д push хийнэ; `NuGet/login@v1` (OIDC, `id-token: write`) богино хугацааны key авдаг тул repo secret хэрэггүй.
  - Яагаад: `dotnet add package GeregeSystems.EidMongolia.Pades` шууд ажиллахгүй байсан (зөвхөн GitHub Release `.nupkg`).
  - Хаана: nuget.org Trusted Publishing бодлого — эзэн `geregecore`, glob `GeregeSystems.EidMongolia.*`, workflow `release.yml`.
  - Шалгасан: workflow синтакс; бодит push дараагийн tag (0.3.0) дээр.
