# WORM Audit screenshots

Refreshed after record-screen polish **2026-10-13 (America/Chicago)** from the rebuilt test-scope demo using
packaged Next UI 1.0.0-RC.14 and connected Edge through the browser screenshot
and viewport tools. All files are JPEG viewport captures, below 300 KB each.

```powershell
./mvnw.cmd -o test-compile exec:java "-Dexec.classpathScope=test" "-Dexec.mainClass=com.kingsrook.qbits.wormaudit.demo.WormAuditDemoServer" "-Dexec.args=8105"
```

Open <http://localhost:8105/app/worm_audit/>. Port 8105 isolates this rebuilt instance from earlier demos. The seed creates genuine verification
results and exports over synthetic data. Records captured: FAIL verification #8,
PASS verification #15, sealed export #15, and chain link #329.

Required matrix: home at **390, 1440, 1920 px**, and all four records at **390,
1440 px**, each in **light and dark**. Heights are 844, 1000 and 1080 px respectively.
The existing supplementary 390 px light purge-history capture was refreshed too.
Theme changes used Preferences and were restored to light; the temporary viewport override was reset afterward.

Every image was visually inspected. At each capture, the live DOM was checked after responsive layout settled for
page-level horizontal overflow (`document.documentElement.scrollWidth > innerWidth`)
and all rendered inner horizontal scrollers (`scrollWidth > clientWidth + 1` with
computed `overflow-x` of `auto` or `scroll`). The scan included content below the
viewport, including loaded child lists. Mobile verification accordions were also explicitly expanded and checked after their child rows loaded. There were **zero** page overflow failures
and **zero** inner horizontal scrollers. Each home/verification/export view had
one vertical scroll container (main); chain records had none. No double scrollbars
were found. Long hashes, object versions and failure diagnostics wrap on mobile.
No CSS or DOM overrides were injected for the captures.

All five tables have explicit field labels and meaningful record-label formats.
Verification uses full-width Result, Scope, Run, and Chain links sections. Every
child-list widget and section declares 12 grid columns. Kind and outcome use
readable possible values; child queries translate those values too. Hashes stay
complete because RC.5 has no separate list-only field display format. Numeric
chain-reference labels keep the export title concise.

Core RC.5 shares the table label with its sidebar tree node. Existing plural
navigation labels are retained, with singular record titles and record-section
labels. Separate singular table labels and plural sidebar labels require core
support; no application-wide metadata customizer was replaced to work around it.

`./mvnw.cmd -o verify` passed: 79 tests, no failures or errors, and 9
Docker-dependent skips. Checkstyle and JaCoCo coverage gates passed. Metadata
tests cover every field label, record-label formats and fields, verification
section coverage, and 12-column sections and child widgets.

| Screenshot | Viewport | Size | Page horizontal overflow | Inner horizontal scrollers | Double scrollbars |
|---|---|---|---|---|---|
| [worm-audit-chain-link-1440-dark](worm-audit-chain-link-1440-dark.jpg) | 1440 x 1000 | 41.1 KB | None | None | None |
| [worm-audit-chain-link-1440-light](worm-audit-chain-link-1440-light.jpg) | 1440 x 1000 | 41.4 KB | None | None | None |
| [worm-audit-chain-link-390-dark](worm-audit-chain-link-390-dark.jpg) | 390 x 844 | 21.8 KB | None | None | None |
| [worm-audit-chain-link-390-light](worm-audit-chain-link-390-light.jpg) | 390 x 844 | 21.8 KB | None | None | None |
| [worm-audit-home-1440-dark](worm-audit-home-1440-dark.jpg) | 1440 x 1000 | 73.6 KB | None | None | None |
| [worm-audit-home-1440-light](worm-audit-home-1440-light.jpg) | 1440 x 1000 | 72.4 KB | None | None | None |
| [worm-audit-home-1920-dark](worm-audit-home-1920-dark.jpg) | 1920 x 1080 | 84.7 KB | None | None | None |
| [worm-audit-home-1920-light](worm-audit-home-1920-light.jpg) | 1920 x 1080 | 83.6 KB | None | None | None |
| [worm-audit-home-390-dark](worm-audit-home-390-dark.jpg) | 390 x 844 | 30.0 KB | None | None | None |
| [worm-audit-home-390-light](worm-audit-home-390-light.jpg) | 390 x 844 | 28.8 KB | None | None | None |
| [worm-audit-home-390-purges-light](worm-audit-home-390-purges-light.jpg) | 390 x 844 | 29.5 KB | None | None | None |
| [worm-audit-sealed-export-1440-dark](worm-audit-sealed-export-1440-dark.jpg) | 1440 x 1000 | 117.6 KB | None | None | None |
| [worm-audit-sealed-export-1440-light](worm-audit-sealed-export-1440-light.jpg) | 1440 x 1000 | 118.4 KB | None | None | None |
| [worm-audit-sealed-export-390-dark](worm-audit-sealed-export-390-dark.jpg) | 390 x 844 | 38.4 KB | None | None | None |
| [worm-audit-sealed-export-390-light](worm-audit-sealed-export-390-light.jpg) | 390 x 844 | 37.3 KB | None | None | None |
| [worm-audit-verification-fail-1440-dark](worm-audit-verification-fail-1440-dark.jpg) | 1440 x 1000 | 53.6 KB | None | None | None |
| [worm-audit-verification-fail-1440-light](worm-audit-verification-fail-1440-light.jpg) | 1440 x 1000 | 54.1 KB | None | None | None |
| [worm-audit-verification-fail-390-dark](worm-audit-verification-fail-390-dark.jpg) | 390 x 844 | 28.1 KB | None | None | None |
| [worm-audit-verification-fail-390-light](worm-audit-verification-fail-390-light.jpg) | 390 x 844 | 27.8 KB | None | None | None |
| [worm-audit-verification-pass-1440-dark](worm-audit-verification-pass-1440-dark.jpg) | 1440 x 1000 | 49.0 KB | None | None | None |
| [worm-audit-verification-pass-1440-light](worm-audit-verification-pass-1440-light.jpg) | 1440 x 1000 | 49.7 KB | None | None | None |
| [worm-audit-verification-pass-390-dark](worm-audit-verification-pass-390-dark.jpg) | 390 x 844 | 23.5 KB | None | None | None |
| [worm-audit-verification-pass-390-light](worm-audit-verification-pass-390-light.jpg) | 390 x 844 | 23.4 KB | None | None | None |
