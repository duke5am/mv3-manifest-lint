# mv3-manifest-lint

A static linter for **Chrome Manifest V3** extensions. It reads `manifest.json`
and the files that manifest references, then reports the mistakes that get an
extension rejected from the Chrome Web Store or leave it broken at runtime
once it is packaged and installed.

- **Standard library only.** No dependencies, nothing to install, no network
  access, no telemetry.
- **Static.** It never loads the extension into a browser.
- **37 rules**, each with a severity, an explanation of *why* it matters, and
  a concrete fix.
- Ships with a deliberately clean example and a deliberately broken one, plus
  175 tests including a negative control that requires the clean example to
  produce **exactly zero** findings.

## Install-free usage

There is nothing to install. Copy the directory, or just the single file, and
run it with Python 3.10+:

```bash
python3 mv3_manifest_lint.py <extension-dir> [--json] [--severity high|medium|low] [--quiet] [--list-rules]
```

The target can be either the extension directory (the one containing
`manifest.json`) or the path to a `manifest.json` itself. Referenced files are
always resolved relative to the extension root — the directory holding the
manifest — which is what Chrome does when it loads the unpacked extension.

| Flag | Effect |
| --- | --- |
| *(no flags)* | Human-readable report at the `low` threshold (everything). |
| `--json` | Machine-readable JSON on stdout, including a `failing` array for the active threshold. |
| `--severity <level>` | Minimum severity to report: `high`, `medium` or `low`. Abbreviations such as `med` are accepted. |
| `--quiet` | Print nothing when there is nothing to report; findings are still printed. |
| `--list-rules` | Print the rule reference and exit `0`. |
| `--version`, `--help` | Usual meanings. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above the requested `--severity` threshold. |
| `1` | At least one finding at or above the threshold. |
| `2` | Usage error, unreadable or missing path, or `manifest.json` is not valid JSON (or is not a JSON object). |

A CI check is therefore just:

```bash
# Fail the build on anything high or medium; show low findings separately.
python3 mv3_manifest_lint.py dist/unpacked --severity medium
```

### Severities

| Severity | Meaning |
| --- | --- |
| `high` | Breaks the extension at runtime, or is a hard Chrome manifest / packaging error. Remotely hosted code lives here too: it is a declared MV3 policy violation. |
| `medium` | Not fatal, but will very likely cost you a store rejection or a broken experience (no 128px icon, description over the store's 132-character limit). |
| `low` | Informational, or a *review* risk for a human to judge. |

## Real example output

Both blocks below are the exact output of the shipped examples on this
machine, pasted unedited.

### `examples/bad` — a deliberately broken MV2 extension

```console
$ python3 mv3_manifest_lint.py examples/bad; echo "exit=$?"
mv3-manifest-lint 1.0.0
extension root : /root/money_making/free/mv3-manifest-lint/examples/bad
manifest       : /root/money_making/free/mv3-manifest-lint/examples/bad/manifest.json
threshold      : low -- showing 31 of 31 finding(s)

HIGH REMOTE-001  background.js:7
      importScripts("https://cdn.example.invalid/analytics.js") fetches executable code over the network. MV3 allows importScripts only for packaged files.
      fix: Vendor the script into the package and call importScripts('lib/vendor.js').

HIGH REMOTE-002  background.js:11
      import("https://cdn.example.invalid/parser.js") pulls a module off the network at runtime. MV3 blocks remotely hosted code.
      fix: Bundle the module into the package and import a relative path.

HIGH REMOTE-003  background.js:22
      eval() is present. The MV3 extension_pages CSP has no 'unsafe-eval', so this call throws at runtime.
      fix: Replace eval with JSON.parse for data, a dispatch table for code paths and a real template for strings.

HIGH REMOTE-003  background.js:26
      new Function() compiles a string into code and is blocked by the MV3 extension_pages CSP (no 'unsafe-eval').
      fix: Replace new Function with an explicit function or a lookup table.

HIGH REMOTE-003  content/scrape.js:13
      eval() is present. The MV3 extension_pages CSP has no 'unsafe-eval', so this call throws at runtime.
      fix: Replace eval with JSON.parse for data, a dispatch table for code paths and a real template for strings.

HIGH ACTION-001  manifest.json
      browser_action is an MV2 key. MV3 merged both into action, and Chrome ignores browser_action, so the toolbar button never appears.
      fix: Rename browser_action to action.

HIGH ACTION-001  manifest.json
      page_action is an MV2 key. MV3 merged both into action, and Chrome ignores page_action, so the toolbar button never appears.
      fix: Rename page_action to action.

HIGH BG-001  manifest.json
      background.scripts lists background.js. MV3 ignores the key entirely, so the background code never runs.
      fix: Replace it with background.service_worker pointing at one worker file.

HIGH CSP-001  manifest.json
      content_security_policy sets script-src to include https://cdn.example.invalid. Scripts may only load from inside the extension package; a remote script origin is remotely hosted code.
      fix: Vendor those scripts into the package and reduce script-src to 'self'.

HIGH CSP-002  manifest.json
      content_security_policy sets script-src to include 'unsafe-eval'. Chrome refuses to load an MV3 extension that permits eval().
      fix: Remove 'unsafe-eval'. Use 'wasm-unsafe-eval' only if you genuinely need WebAssembly.

HIGH FILE-001  manifest.json
      web_accessible_resources points at "images/logo.png", which is not in the extension directory. The manifest itself stays valid, so this shows up only after packaging: the feature is dead, or Chrome refuses the package.
      fix: Add the missing file, or correct the path. Paths resolve relative to the extension root (the directory holding manifest.json).

HIGH FILE-001  manifest.json
      options_page points at "options.html", which is not in the extension directory. The manifest itself stays valid, so this shows up only after packaging: the feature is dead, or Chrome refuses the package.
      fix: Add the missing file, or correct the path. Paths resolve relative to the extension root (the directory holding manifest.json).

HIGH MATCH-001  manifest.json
      content_scripts[0].matches contains "https://example.invalid", which has no path component. A match pattern needs scheme://host/path, so this is invalid; "https://example.invalid/*" is what you meant. An invalid pattern makes Chrome refuse the whole manifest.
      fix: Change it to "https://example.invalid/*", or narrow it to the exact path you inject into.

HIGH META-003  manifest.json
      version "1.2.3-beta" is not 1 to 4 dot-separated integers. Chrome rejects suffixes, a leading v and empty segments.
      fix: Use a plain dotted integer version such as "1.2.0".

HIGH MV2-001  manifest.json
      manifest_version is 2. Chrome no longer accepts Manifest V2 extensions, so this cannot be loaded in current Chrome and cannot be published to the Chrome Web Store.
      fix: Port to MV3: action instead of browser_action, a service worker instead of a background page, host_permissions for origins, and chrome.scripting for injection.

HIGH PERM-001  manifest.json
      "https://example.invalid/*" in permissions is a host pattern, not an API permission. Origins belong in host_permissions; as written this grants nothing.
      fix: Move it to host_permissions.

HIGH PERM-001  manifest.json
      "<all_urls>" in permissions is a host pattern, not an API permission. Origins belong in host_permissions; as written this grants nothing.
      fix: Move it to host_permissions.

HIGH PERM-001  manifest.json
      "*://*.example.invalid/*" in permissions is a host pattern, not an API permission. Origins belong in host_permissions; as written this grants nothing.
      fix: Move it to host_permissions.

HIGH PERM-002  manifest.json
      "storage" in host_permissions is an API permission name, not a match pattern. host_permissions accepts patterns only, so the permission is never granted and the API call fails at runtime.
      fix: Move it to permissions.

HIGH PERM-002  manifest.json
      "downloads" in host_permissions is an API permission name, not a match pattern. host_permissions accepts patterns only, so the permission is never granted and the API call fails at runtime.
      fix: Move it to permissions.

HIGH WAR-001  manifest.json
      web_accessible_resources is an array of 2 string(s) (images/logo.png, lib/helper.js). That is the MV2 form; MV3 requires an array of objects carrying resources and matches.
      fix: Rewrite as [{"resources": [...], "matches": ["<all_urls>"]}], with the narrowest matches that work.

HIGH HTML-001  popup.html:14
      <script src="https://cdn.example.invalid/jquery-4.0.0.min.js"> loads script from outside the package. MV3 blocks remotely hosted code, and the store rejects it.
      fix: Download the file, commit it inside the extension, and reference it with a relative path.

HIGH HTML-002  popup.html:15
      Inline <script> block. The MV3 extension_pages CSP is "script-src 'self'" with no 'unsafe-inline', so this block never executes.
      fix: Move the code into a .js file in the package and load it with <script src="..."></script>.

HIGH HTML-003  popup.html:21
      onclick="..." is inline script. The MV3 extension_pages CSP has no 'unsafe-inline', so the handler never runs.
      fix: Attach the handler from a script file with addEventListener.

HIGH HTML-003  popup.html:22
      onmouseover="..." is inline script. The MV3 extension_pages CSP has no 'unsafe-inline', so the handler never runs.
      fix: Attach the handler from a script file with addEventListener.

HIGH FILE-001  popup.js
      An extension page references "popup.js", which is not in the extension directory. The page loads with a missing asset and the feature is dead.
      fix: Add the file, or fix the reference in the HTML page.

MED  BG-002  manifest.json
      background.persistent is True, which had meaning only for an MV2 background page. A service worker is always event-driven.
      fix: Delete the key and move long-lived state into chrome.storage.

MED  ICON-001  manifest.json
      icons has no 128 entry. The Chrome Web Store listing requires a 128x128 icon; Chrome can render its own icon but the listing cannot.
      fix: Add "128": "icons/icon128.png".

MED  META-002  manifest.json
      description is 191 characters. The Chrome Web Store listing field is capped at 132, so this is refused at upload.
      fix: Shorten it by at least 59 characters.

LOW  MATCH-002  manifest.json [review convention]
      content_scripts[0].matches uses <all_urls>. Chrome allows it, but injecting into every origin is the widest request available and attracts Web Store review scrutiny. (Web Store review convention, not a runtime error.)
      fix: List the specific origins you need, or drop content_scripts in favour of activeTab plus chrome.scripting.

LOW  HTML-004  popup.html:9 [review convention]
      <link rel="stylesheet" href="https://fonts.example.invalid/inter-1.0/inter.css"> pulls CSS from outside the package. Style sources are not pinned to 'self' so Chrome allows it, but it tells a third party the extension is in use and it breaks offline. (Review convention.)
      fix: Vendor the stylesheet into the package.

summary: 26 high, 3 medium, 2 low (31 total)
exit=1
```

Note the two `FILE-001` findings on `manifest.json` and the last one on
`popup.js`: those reference `images/logo.png`, `options.html` and `popup.js`,
none of which exist in `examples/bad`. That is the class of bug that only shows
up after packaging, which is why the check follows references into HTML as well
as into the manifest.

### `examples/good` — a store-ready MV3 extension

```console
$ python3 mv3_manifest_lint.py examples/good; echo "exit=$?"
mv3-manifest-lint 1.0.0
extension root : /root/money_making/free/mv3-manifest-lint/examples/good
manifest       : /root/money_making/free/mv3-manifest-lint/examples/good/manifest.json
threshold      : low -- showing 0 of 0 finding(s)

No findings. manifest.json is clean against every rule
this tool implements (see --list-rules for the list).
exit=0
```

Zero findings **at the lowest threshold**, not merely "no high findings". This
example is a real directory tree (`manifest.json`, a service worker, popup and
options pages, a content script, CSS and four PNG icons), and the test suite
asserts that it stays completely silent.

### Filtering the noise

```console
$ python3 mv3_manifest_lint.py examples/bad --severity high
...
summary: 26 high, 3 medium, 2 low (31 total)
```

The summary counts every finding, while the report body only shows those at or
above the threshold. `--severity` therefore never hides the fact that lower
findings exist.

### JSON

```console
$ python3 mv3_manifest_lint.py examples/good --json
{
  "tool": "mv3-manifest-lint",
  "version": "1.0.0",
  "root": "/…/examples/good",
  "manifest": "/…/examples/good/manifest.json",
  "error": null,
  "summary": { "high": 0, "medium": 0, "low": 0, "total": 0 },
  "findings": [],
  "threshold": "low",
  "failing": []
}
```

Each finding object carries `rule`, `severity`, `title`, `message`, `fix`,
`file`, `line` (or `null`), `review`, and an optional `context` object with the
specific value at fault.

## Tests

```bash
python3 -m unittest discover -s tests -v     # or: python3 run_tests.py [-v]
```

Both invocations work and run the same suite. Current state on this machine:

```console
$ python3 run_tests.py
...............................................................................................................................................................................
----------------------------------------------------------------------
Ran 175 tests in 9.791s

OK

ran 175 tests: 175 passed, 0 failed, 0 errored, 0 skipped
```

331 `assert*` call sites across three modules:

- `tests/test_rules.py` — one test per rule and per false-positive guard. Every
  test starts from a manifest that produces zero findings and changes exactly
  one thing.
- `tests/test_control_examples.py` — the **negative control**. `examples/good`
  must produce exactly zero findings at `low`, `medium` and `high`, and
  `examples/bad` must keep exercising a broad slice of the rule set.
- `tests/test_cli.py` — the CLI contract in a subprocess: exit codes, every
  flag, severity filtering, the stdout/stderr split, and JSON structure.

Malformed input is covered explicitly: invalid JSON, truncated JSON, a JSON
array, a JSON string, an empty file, and a missing `manifest.json` all produce
exit code `2` and a parse error rather than a traceback.

Scratch extension trees are written under `.test-scratch/` inside the project
directory and removed after each test module, never under `/tmp`.

## What the rules cover

`python3 mv3_manifest_lint.py --list-rules` prints the full reference
(37 rules). In summary:

| Area | Rules |
| --- | --- |
| Manifest version and MV2 leftovers | `META-004`, `MV2-001`, `BG-001`, `BG-002`, `BG-003`, `ACTION-001` |
| Remote / dynamically evaluated code | `CSP-001`, `CSP-002`, `CSP-003`, `CSP-005`, `REMOTE-001`, `REMOTE-002`, `REMOTE-003`, `HTML-001`, `HTML-002`, `HTML-003` |
| CSP shape | `CSP-004` |
| Permissions | `PERM-001`, `PERM-002`, `PERM-005`, `PERM-006` |
| `web_accessible_resources` | `WAR-001`, `WAR-002`, `WAR-003`, `WAR-004`, `WAR-005` |
| Match patterns | `MATCH-001`, `MATCH-002` |
| Store metadata | `META-001`, `META-002`, `META-003`, `ICON-001`, `ICON-002` |
| Missing referenced files | `FILE-001`, `FILE-002` |
| Chrome version floor | `CHROME-001` |
| Review-risk notices | `HTML-004` |

### Hard rules versus review conventions

Rules backed by a hard runtime or manifest-validation requirement are reported
without qualification. Two rules are explicitly labelled in the output as
`[review convention]` and carry `"review": true` in JSON:

- `MATCH-002` — `<all_urls>` where a narrower pattern would do. Chrome allows
  it; it is the widest possible request and attracts Web Store review
  scrutiny. This is a review concern, not a defect.
- `HTML-004` — a remote `<link rel=stylesheet>`. Style sources are not pinned
  to `'self'` the way script sources are, so Chrome loads it; it leaks use of
  the extension to a third party and breaks offline. Review concern, not an
  error.

`WAR-003` (a `declarativeNetRequest` ruleset file that is not listed in
`web_accessible_resources`) is also flagged as review-risk, because this linter
cannot load the extension into Chrome to confirm the failure.

`CHROME-001` only fires for APIs whose minimum Chrome version is documented and
stable enough to name: the `offscreen` permission (Chrome 109), `sidePanel`
(Chrome 114) and `userScripts` (Chrome 120). It stays silent otherwise, on the
principle that a wrong minimum version is worse than no rule at all.

## What this does not do

Being explicit about the limits, because a clean run from this tool is **not**
a guarantee that the Chrome Web Store will accept your extension:

- **It is static analysis only.** It never loads the extension into Chrome, so
  it cannot tell you whether the extension actually works. A clean run means
  the files parse and the shapes are right, not that the code runs.
- **It does not check store policy compliance beyond the rules listed above.**
  Single-purpose policy, deceptive behaviour, trademark and branding rules,
  affiliate-link disclosure, data-use disclosures in the developer dashboard,
  privacy-policy requirements, and the review outcome itself are all outside
  its scope.
- **It cannot know whether a permission is *justified*.** It can tell you that
  `"tabs"` is in the wrong array, but not that you do not need it. Permission
  minimisation is a judgement call the reviewer makes, and only you can decide
  it.
- **It is not a security audit.** It spots specific patterns that are
  mechanically detectable (remote script, `eval`, remote `importScripts`). It
  does not reason about XSS, message-passing trust boundaries between content
  scripts and the service worker, or supply-chain risk in your dependencies.
- **It does not validate every manifest key.** Keys outside the rule set are
  not type-checked, and it will not catch a typo in a key it does not know
  about.
- **Its match-pattern parsing is deliberately conservative.** For a pattern it
  does not recognise, it stays silent rather than guessing. A path of exactly
  `/` (`https://example.com/`) is accepted, because that is a path component.
- **Rule 132 characters is the store *listing field* limit.** If you upload
  through a different channel, or the limit changes, that finding may be
  wrong — treat the message text as the source of truth rather than the rule
  ID.
- **Chrome behaviour changes.** Manifest requirements and Web Store policies
  are revised over time. This tool encodes what was true when it was written
  and verified on this machine; re-read the finding text before dismissing it.
- **No auto-fix.** It reports and explains. It does not rewrite your manifest.

If you want a clean run to mean more, run it as a pre-package step and let the
`FILE-001` findings stop the release — that is the class of bug it is uniquely
good at catching.

## Layout

```
mv3-manifest-lint/
├── mv3_manifest_lint.py     # the whole linter and CLI (standard library only)
├── run_tests.py             # convenience runner for the suite
├── tests/
│   ├── fixtures.py          # scratch-tree helpers + the clean baseline manifest
│   ├── test_rules.py        # one test per rule, plus false-positive guards
│   ├── test_control_examples.py  # negative control: examples/good must be silent
│   └── test_cli.py          # exit codes, flags, JSON contract
├── examples/
│   ├── good/                # store-ready MV3 extension: zero findings
│   └── bad/                 # deliberate MV2-era mess: 31 findings
├── make_icons.py            # regenerates the example PNG icons
├── LICENSE
└── README.md
```

Fixtures contain no secrets and no realistic credentials: every hostname is
under `.invalid` (reserved by RFC 2606 and guaranteed never to resolve) and
every icon is a generated placeholder.

## Licence

MIT. See [`LICENSE`](LICENSE).

```
MIT License

Copyright (c) 2026 duke5am

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

→ **Chrome MV3 Extension Starter**: <!-- GUMROAD-LINK -->