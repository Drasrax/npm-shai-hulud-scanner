# NPM Supply Chain Security Scanner

Security toolkit for detecting supply chain vulnerabilities in NPM projects, designed to detect patterns from the major 2025-2026 npm supply chain attacks:

- **CVE-2025-54313** (Scavenger malware - July 2025)
- **Shai-Hulud worm** (September 2025) and **Shai-Hulud 2.0 "The Second Coming"** (November 2025)
- **Mini Shai-Hulud / TeamPCP family** (April-June 2026): SAP CAP, Bitwarden CLI, TanStack (**CVE-2026-45321**), AntV, Miasma (Red Hat), Hades (PyPI)
- **June-July 2026 campaigns** by other actors reusing the same playbook: Mastra / `easy-day-js` (Sapphire Sleet), Injective SDK, jscrambler / IronWorm, the aone-cli RAT cluster, Joyfill / PolinRider
- **ChainDrop** (August 2026): the keyv / cacheable worm — 444 packages, 2259 versions, ~2 billion monthly installs, with its C2 list held in an Ethereum contract
- **Flooding Dropper** (August 2026): ~1000 dependency-confusion packages whose dropper runs on `require()`, not on an install hook

## Purpose

Detect and notify security vulnerabilities in NPM (and now PyPI) dependencies, including:

- **7499 compromised package versions across 3599 npm packages and 95 PyPI projects** (Shai-Hulud v1/v2 + CVE-2025-54313 + the 2026 Mini Shai-Hulud waves + the June-August 2026 campaigns)
- **Transitive dependencies**: known-compromised packages are matched in `package-lock.json` (v1/v2/v3 formats) and installed `node_modules`, not just direct `package.json` dependencies
- **Cross-ecosystem coverage**: npm + PyPI (Hades wave), with Maven spillover documented
- Bun-runtime loaders used for EDR evasion (`setup.mjs`, `execution.js`, `bw1.js`, `_index.js`, `Math_Symbol.js`, pinned Bun v1.3.13)
- **Import-time implants**: the entry point (`main`, or `index.js`) of every installed package is analysed, because a payload that runs on `require()` never touches a lifecycle script
- **Dependency-confusion version inflation** (`9999.0.0`, `1.0.999`) in the lockfile and in `node_modules`
- Blockchain dead-drop C2 (EtherHiding): Ethereum, Tron, Aptos, BSC and ICP canisters
- Malware persistence via agent/IDE config files (survives `npm uninstall`)
- OIDC / Trusted-Publishing abuse and GitHub commit-pinned tarball injection
- Shai-Hulud 2.0 Bun payloads (`setup_bun.js`, `bun_environment.js`)
- Typosquatting attempts
- Injected malicious code (DLL/SO files, obfuscated scripts)
- Suspicious installation scripts
- Worm-like/propagation behaviors
- C2 domain communication
- Cloud metadata endpoint (IMDS) access — AWS (including ECS `169.254.170.2`), GCP, Azure, Alibaba, Tencent
- Out-of-band exfiltration channels (Interactsh / OAST, Burp Collaborator, Pipedream, Telegram bot API, Zapier hooks, Serveo and ngrok tunnels)

## Files

- `npm-supply-chain-detector.py` - Main Python detection script
- `scan-npm-security.sh` - Bash automation and monitoring script
- `malicious-patterns.json` - Malicious patterns database (production; auto-synced from the IOC database by `update-patterns.py`)
- `shai-hulud-iocs.json` - Extended IOCs database (3599 npm packages / 7499 versions, 95 PyPI projects, 301 hashes, C2 domains, one section per campaign family) — the file loaded by the Python detector
- `update-patterns.py` - Pattern database generator/updater (regenerates `shai-hulud-iocs.json` and syncs `malicious-patterns.json`)

## Installation

```bash
# Clone or download scripts
chmod +x npm-supply-chain-detector.py scan-npm-security.sh

# Check prerequisites
./scan-npm-security.sh --help
```

### Prerequisites
- Python 3.6+
- npm/node installed
- NPM project with package.json

## Usage

### Simple scan

```bash
# Scan current directory
python3 npm-supply-chain-detector.py

# Scan specific project
python3 npm-supply-chain-detector.py /path/to/project

# With detailed report
python3 npm-supply-chain-detector.py -v -o markdown -f report.md
```

### Automation script

```bash
# Basic scan
./scan-npm-security.sh

# Continuous monitoring (scan every 5 minutes)
./scan-npm-security.sh -c -i 300

# Deep scan with save
./scan-npm-security.sh -d -f security-report.md -o markdown /project

# With webhook notifications (Slack, Discord, etc.)
./scan-npm-security.sh -w https://hooks.slack.com/services/XXX

# Quarantine suspicious packages (moves to .npm-quarantine/)
./scan-npm-security.sh --quarantine

# Restore quarantined packages if false positive
./.npm-quarantine/restore.sh
```

### Available options

#### Python Script (`npm-supply-chain-detector.py`)
- `-o, --output`: Output format (json, text, markdown)
- `-f, --file`: Save report to file
- `-v, --verbose`: Verbose mode
- `--webhook`: Webhook URL for notifications

#### Bash Script (`scan-npm-security.sh`)
- `-c, --continuous`: Continuous monitoring mode
- `-i, --interval`: Interval between scans (seconds)
- `-d, --deep`: Deep scan (includes npm audit, outdated packages)
- `--quarantine`: **Move suspicious packages to quarantine folder**
- `--update-patterns`: Update patterns from file

## Quarantine Feature

The `--quarantine` option automatically isolates compromised packages:

**How it works:**

1. Scans for critical vulnerabilities
2. Identifies compromised packages from scan results
3. Moves packages from `node_modules/` to `.npm-quarantine/packages/`
4. Creates JSON manifest with metadata (versions, paths, timestamps)
5. Generates automatic `restore.sh` script

**Directory structure created:**
```
.npm-quarantine/
├── packages/              # Isolated packages
│   ├── package-name/
│   └── @scope_package-name/
├── logs/                  # Scan logs
├── quarantine-manifest-*.json  # Metadata
└── restore.sh            # Restoration script
```

**To restore (if false positive):**
```bash
cd .npm-quarantine
./restore.sh              # Interactive confirmation required
```

## Detections

### 1. Known compromised packages (7499 versions)

Matched in three places: direct dependencies in `package.json`, the full dependency tree in `package-lock.json` (v1 nested tree and v2/v3 flat `packages` map), and packages actually installed under `node_modules` — so a compromised package pulled in three levels deep is still flagged.

**CVE-2025-54313 (Scavenger - July 2025):**

- eslint-config-prettier (8.10.1, 9.1.1, 10.1.6, 10.1.7)
- eslint-plugin-prettier (4.2.2, 4.2.3)
- synckit (0.11.9)
- @pkgr/core (0.2.8)
- napi-postinstall (0.3.1)
- got-fetch (5.1.11, 5.1.12)
- is (3.3.1, 5.0.0)
- @crowdstrike/node-exporter (0.2.2)
- @crowdstrike/threat-center (1.205.2)
- tailwind-toucan-base (5.0.2)
- **Shai-Hulud 2.0 (Wiz, Nov 27 2025)**: ~470 packages / versions (e.g. `@asyncapi/*`, `@actbase/*`, `@accordproject/*`, `@antstackio/*`, etc.) – see `shai-hulud-iocs.json` for the full list

**September 2025 "qix" wave (chalk / debug):**

The largest npm incident by reach. A phishing mail against one maintainer account poisoned a single version of each of ~20 micro-utilities that sit under almost every JavaScript toolchain, plus a tail of unrelated packages published from other stolen accounts in the same window — **107 packages** in total, recorded at their exact versions:

- `chalk@5.6.1`, `debug@4.4.2`, `ansi-styles@6.2.2`, `strip-ansi@7.1.1`, `color-convert@3.1.1`, `color-name@2.0.1`, `supports-color@10.2.1`, `wrap-ansi@9.0.1`, `slice-ansi@7.1.1`, `ansi-regex@6.2.1`, `is-arrayish@0.3.3`, `error-ex@1.3.3`, `simple-swizzle@0.2.3`, `has-ansi@6.0.1`, `chalk-template@1.1.1`, `backslash@0.2.1`, `supports-hyperlinks@4.1.1`, `proto-tinker-wc@0.1.87`
- `duckdb@1.3.3`, `@duckdb/node-api@1.3.3`, `@duckdb/node-bindings@1.3.3`, `@duckdb/duckdb-wasm@1.29.2`, `prebid@10.9.1/10.9.2`, and ~80 more (see `shai-hulud-iocs.json`)

Only **one** version of each of these is malicious, which is why they are recorded as exact versions rather than wildcards — see the note on `OVERBROAD_WILDCARDS` in `update-patterns.py`.

**Shai-Hulud worm (September 2025):**

- CrowdStrike packages (@crowdstrike/*)
- @ctrl/tinycolor (4.1.1, 4.1.2)
- @nativescript-community/* packages
- @operato/* packages
- @things-factory/* packages
- Many others (see shai-hulud-iocs.json)

**Shai-Hulud 2.0 (November 2025, Unit42 & Wiz)**

- New payloads: `setup_bun.js`, `bun_environment.js`
- bun_environment.js hashes: `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`, `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`, `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`
- setup_bun.js hash: `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`
- GitHub exfiltration: repo description "Sha1-Hulud: The Second Coming"
- Possible destructive fallback (`rm -rf ~` / `$HOME`)

**Mini Shai-Hulud / TeamPCP family (April-June 2026)**

Threat actor **TeamPCP (aka UNC6780)**, who open-sourced their "Mini Shai-Hulud" malware, triggering a cascade of waves (and copycats). All of them use a **Bun loader** (EDR evasion) and exfiltrate via GitHub dead-drop repositories created on the victim's own account:

| Wave | Date | Ecosystem | Key packages |
|------|------|-----------|--------------|
| Bitwarden CLI ("The Third Coming") | 2026-04-22 | npm | `@bitwarden/cli@2026.4.0` (via Checkmarx breach) |
| SAP CAP ("A Mini Shai-Hulud has Appeared") | 2026-04-29 | npm | `mbt`, `@cap-js/sqlite`, `@cap-js/postgres`, `@cap-js/db-service` |
| TanStack (**CVE-2026-45321**) | 2026-05-11 | npm + PyPI | 42 `@tanstack/*` pkgs, `@mistralai/mistralai`, `@uipath/cli` (OIDC/Trusted-Publishing hijack, valid SLSA provenance) |
| AntV ("Here We Go Again") | 2026-05-19 | npm | `@antv/g2,g6,l7,s2`, `echarts-for-react`, `timeago.js`, `size-sensor` (compromised `atool` maintainer account) |
| Miasma ("The Spreading Blight") | 2026-06-01 | npm | `@redhat-cloud-services/*` (via GitHub Actions OIDC) |
| Miasma "Phantom Gyp" | 2026-06-03 | npm | 68 packages (`@vapi-ai/server-sdk`, `ai-sdk-ollama`, `autotel-*`) executing through **`binding.gyp`**, which survives `--ignore-scripts` |
| Hades ("The End for the Damned") | 2026-06-07 | **PyPI** | 19 projects via `*-setup.pth` hook → Bun → `_index.js` |
| Hades wave 2 | 2026-06-08 | **PyPI** | 19 further projects; split-loader `.pth` that hunts `sys.path` for any `_index.js`, plus trojanized `.abi3.so` wheels |
| Miasma via hijacked GitHub Action | 2026-06-24 | Actions + npm | 23 tags of `codfish/semantic-release-action` rewritten; LeoPlatform/RStreams packages trojanized |
| Miasma downstream | 2026-06-26 | npm | 22 `@immobiliarelabs/*` Backstage plugin versions |
| Miasma RAT (AsyncAPI) | 2026-07-14 | npm | `@asyncapi/*` via a GitHub Actions pwn-request, published with **valid OIDC/SLSA provenance** |

The **AntV** entry deserves a note: it was previously recorded with 9 packages. Checking the OSSF/OpenSSF `malicious-packages` feed behind the OSV `MAL-2026-*` records puts the real scope at **324 packages / 645 versions**, so the database understated that wave by a factor of about 35.

Two further families are tracked alongside these: **IronWorm** (2026-06-03, 37 npm packages via the compromised `asteroiddao` account — a Rust worm with an eBPF rootkit, which JFrog calls Shai-Hulud's "rustier cousin") and **TrapDoor** (2026-05-19, 34 attacker-created packages across npm, PyPI and crates.io that poison `CLAUDE.md` and `.cursorrules`).

**The earliest wave covered is now TeamPCP's Trivy compromise (2026-02-27 to 03-23)**, which is the one worth knowing about even if you use none of the packages above: the actor force-pushed 76 of 77 `aquasecurity/trivy-action` tags to malicious commits, published backdoored `aquasec/trivy` Docker images, and hit the Checkmarx KICS and AST actions — the security tooling itself became the delivery vehicle. The companion **CanisterWorm** npm worm spread across 71 packages (`@emilgroup/*`, `@opengov/*`, `@automagik/genie`, `pgserve`…) using Internet Computer canisters as dead-drop C2.

**PyPI coverage now reaches back before the npm waves.** TeamPCP's earliest `.pth`-loader wave (2026-03-24) hit **`litellm` 1.82.7/1.82.8** — a package with roughly 95M downloads a month — along with **`telnyx`** 4.87.1/4.87.2 and **`xinference`** 2.6.0-2.6.2. The loader (`litellm_init.pth`) runs on *every Python interpreter start*, not just on install. A separate typosquat cluster (2026-07-07) shipped 13 npm and 4 PyPI packages impersonating Paysafe, Skrill and Neteller; those were created by the attacker rather than hijacked, so every published version is treated as malicious.

Two standalone PyPI compromises using the same tradecraft are also covered: **`lightning`** (PyTorch Lightning) 2.6.2/2.6.3 on 2026-04-30, which hid a Bun infostealer in a `_runtime` directory that runs on import — note that the sibling `pytorch-lightning` distribution was *not* affected — and **`mrmustard`** 0.7.4 (XanaduAI) on 2026-07-24, an artifact-only injection where the poisoned wheel went straight to PyPI while the GitHub source stayed clean, so comparing against the repository would not have revealed it.

Novel TTPs covered: **Bun v1.3.13 runtime** (evasion), **persistence via agent/IDE config files** (`.claude`/`.vscode`/`.cursor`, survives `npm uninstall`), **OIDC/Trusted-Publishing abuse**, **"living-off-trusted-host" exfiltration** (`api.anthropic.com/v1/api`, `filev2.getsession.org`), and **destructive wipe** triggered on token invalidation.

**June-July 2026 campaigns (other actors, same playbook)**

The period after Hades is dominated by threat actors who are *not* Shai-Hulud but reuse its supply-chain techniques. They are tracked in their own `npm_campaigns_h2_2026` section with separate attribution:

| Campaign | Date | Scope | What makes it notable |
|----------|------|-------|-----------------------|
| Mastra AI / `easy-day-js` | 2026-06-17 | 144 npm packages | A `dayjs` typosquat silently added as a dependency across the whole `@mastra` scope; obfuscated postinstall drops the `protocal.cjs` RAT (Sapphire Sleet / BlueNoroff, DPRK) |
| Injective Labs SDK | 2026-07-08 | 18 `@injectivelabs/*` @ 1.20.21 | **No install hook at all** — hooks `PrivateKey.fromMnemonic/fromHex/generate` and exfiltrates at runtime, disguised as `trackKeyDerivation` telemetry |
| jscrambler / **IronWorm** | 2026-07-11 | 5 versions + 4 plugins | Cross-platform Rust infostealer; 8.14.0-8.17.0 use a preinstall hook, 8.18.0/8.20.0 switch to **import-time execution** to defeat `--ignore-scripts` |
| aone-cli RAT cluster | 2026-07-28 | 19 packages | Capability **split across a benign-looking dependency tree**; vm sandbox escape; drops a private Bun runtime at `~/.real/.bin/bun`; poisons `.skills` Python scripts of AI dev tools |
| Joyfill / **PolinRider** | 2026-07-28 | 2 packages (6 beta versions) | C2 resolved from **Tron/Aptos/BSC blockchain transactions**; implant baked into `dist` bundles at build time; worms into the global npm CLI, VS Code, Discord and GitHub Desktop |

Two of these run at **import time rather than through a lifecycle script**, so checking `package.json` hooks alone is no longer sufficient — the scanner hashes `dist` bundle files for exactly this reason.

**August 2026: ChainDrop and Flooding Dropper**

Tracked in their own `npm_campaigns_aug_2026` section.

| Campaign | Date | Scope | What makes it notable |
|----------|------|-------|-----------------------|
| **ChainDrop** (keyv / cacheable) | 2026-08-04 | 444 npm packages / 2259 versions | Provenance was *genuine*; C2 list held in an Ethereum contract; plants hooks in `.claude/settings.json` and `.vscode/tasks.json` |
| **Flooding Dropper** | 2026-08-05 | ~1000 npm packages | Mass dependency confusion; the dropper fires on `require()`, so `--ignore-scripts` does not help |

ChainDrop started at 09:35 UTC with `keyv@6.0.0`. The attackers took over the maintainer's **GitHub** account rather than their npm account, pushed the payload straight to `main` and cut a release immediately — so every poisoned tarball reached npm with a valid provenance attestation signed by GitHub Actions. The signatures were not forged; the tarballs really were built by that repository, in that workflow, on that commit. **Provenance attests build integrity, not source integrity**, which is why signature verification alone would not have caught this wave. From there the worm used the stolen npm tokens (including OIDC trusted publishing) to republish everything within reach, crossing into twelve unrelated organisations in under four hours: `@servicetitan`, `@onereach`, `@or-sdk`, `@ornikar`, `@qlik`, `@nebula.js`, `@deliveroo`, `@picsart` and more. `flat-cache` and `file-entry-cache` ship inside ESLint, so the blast radius reached projects that never named either dependency.

Its C2 is the interesting part: rather than a hardcoded domain, the loader calls `eth_call` against contract `0xE1f2395…3103` on Ethereum mainnet and reads the current endpoint out of the return value (**EtherHiding**), falling back to a GitHub commit search. Taking down a domain does not stop it. The payload also sweeps AI assistant credentials (`~/.claude/credentials.json`, `~/.codex/auth.json`, `~/.cursor/credentials.json`) alongside the usual cloud and CI secrets.

Flooding Dropper is a different problem: roughly a thousand throwaway packages whose names shadow one organisation's internal modules (`bigops-*`, `bnpl-*`, `devplatform-*`, `statist-browser-typed-client-*`), published from disposable accounts mostly in the `35.x.y` range so they win version resolution. The dropper is reached from `index.js` at **import time**, hides its hostnames by assembling them from string fragments at runtime (`["oob-worker.cf100-416.w","orke","rs.","dev"].join("")`), reaches `child_process` via `require("child_"+"process")`, stages its binary as a fake .NET diagnostic tool, and keeps a DNS-TXT channel in reserve for when HTTPS egress is blocked. Neither `--ignore-scripts` nor npm v12's default lifecycle blocking stops any of it.

Because of that second campaign, the scanner now analyses **the entry point of every installed package** (`main`, falling back to `index.js`), not only files with a known-suspicious name. It also flags **version inflation** — a dependency resolved to `9999.0.0` or `1.0.999` — as a warning, since that is the signature of a dependency-confusion win. CalVer versions such as `2024.1.0` are deliberately not matched.

### 2. Typosquatting detection

- Levenshtein distance analysis
- Common substitutions (0→o, 1→i, etc.)
- Dash/underscore variations

### 3. Malicious code patterns

- Credential exfiltration (AWS, npm, SSH, GitHub tokens)
- Remote code execution (curl|sh, eval)
- Obfuscation (base64, atob, XOR encryption)
- Suspicious network communication to C2 domains
- Self-propagation (worm patterns, npm publishing)
- Cloud metadata endpoint (IMDS) access
- **CVE-2025-54313 specific:** DLL/SO loading, logDiskSpace function

### 4. Suspicious installation scripts
- Malicious preinstall/postinstall hooks
- Script download and execution
- npm token manipulation
- **Windows DLL execution** (rundll32, regsvr32)
- Malicious files: node-gyp.dll, loader.dll, version.dll

### 5. Hash-based detection (301 variants)
- **Shai-Hulud bundle.js** (7 SHA-256 hashes)
- **Shai-Hulud 2.0 Bun payloads**: `bun_environment.js` (3 hashes), `setup_bun.js` (1 hash)
- **CVE-2025-54313 Scavenger** (3 SHA-256 hashes)
- **2026 waves**: Mini Shai-Hulud loaders, Miasma `binding.gyp` and `index.js` blobs, IronWorm native payloads (ELF/PE/Mach-O), Hades wheels and `.pth` hooks, and the June-July campaign payloads

Hashing is not limited to a fixed set of payload filenames any more. Because an exact hash match cannot produce a false positive, ordinary bundle names (`index.cjs.js`, `index.es.js`, `index.esm.js`) are hashed too — that is how the Joyfill implants, which live inside `dist` bundles rather than a dedicated dropper file, are caught. `.cjs` files are hashed as well.

### 5b. Install-time execution outside `package.json` (post-npm-v12)

Since npm v12 blocks lifecycle scripts by default, attackers moved elsewhere. Both routes are covered:

- **`binding.gyp` ("Phantom Gyp")** — `node-gyp` evaluates GYP command expansion `<!(cmd)` at build time, which runs even under `npm install --ignore-scripts`. Flagged when the expansion invokes an interpreter or chains shell commands, or when a target compiles nothing (`"type": "none"`) yet still runs a command. A normal addon locating its headers with `<!(node -p "require('node-addon-api').include")` is not reported.
- **Import-time payloads** — implants appended to `dist` bundles that run on `require()`. Matched through the detached-and-hidden `spawn` shape, `node -e` invocation from a dependency, dynamic `Function()` construction, whitespace padding, and IPFS/blockchain second-stage retrieval.

### 5c. Compromised GitHub Actions and AI instruction files

- **Hijacked Actions** — several Actions had their upstream tags force-pushed to attacker commits, including the security tooling itself: **`aquasecurity/trivy-action`** (76 of 77 tags), **`aquasecurity/setup-trivy`** (all 7), **`Checkmarx/kics-github-action`**, **`Checkmarx/ast-github-action`** and `codfish/semantic-release-action` (23 tags). Any reference by tag is reported as critical, since a tag cannot be trusted once it has been force-pushed; a reference pinned to a full 40-character commit SHA is reported as a warning instead, because pinning is what makes it safe. The list is read from the IOC database, so covering a new one takes no code change.
- **AI instruction files** — `CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `.windsurfrules`, `.cursor/rules/*.mdc` and `.github/copilot-instructions.md` are scanned. TrapDoor and the Miasma waves append attacker instructions to these so the coding agent itself performs the exfiltration, often concealed with zero-width or bidirectional Unicode, and paired with a line telling the assistant not to mention it to the user.
  - node-gyp.dll: c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441
  - Scavenger stage 2: 5bed39728e404838ecd679df65048abcb443f8c7a9484702a2ded60104b8c4a9
  - install.js: 32d0dbdfef0e5520ba96a2673244267e204b94a49716ea13bf635fa9af6f66bf

### 6. C2 domain detection
- firebase.su (CVE-2025-54313)
- dieorsuffer.com (CVE-2025-54313)
- smartscreen-api.com (CVE-2025-54313)
- npnjs.com (typosquatting)
- webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7 (Shai-Hulud)
- t.m-kosche.com (Mini Shai-Hulud AntV C2)
- filev2.getsession.org, api.masscan.cloud, git-tanstack.com (TanStack wave)
- audit.checkmarx.cx (Bitwarden wave exfil)
- teams.onweblive.org, maskasd.com (Mastra wave); xemzqli2vu.ai-app.pub and the attacker-registered `aone-*.oss-cn-beijing.aliyuncs.com` staging buckets (aone-cli cluster)
- npm-cache.com, js-mirror.com, pypi-get.com, awqhnjewqjkl.icu (ChainDrop); dl.wel1.ru (Flooding Dropper DNS-TXT fallback)
- Hardcoded **public** IP endpoints in URLs — loopback, link-local and RFC1918 ranges are excluded

A domain hit is reported as **critical**, so this list only contains hosts no honest dependency would contact. Legitimate infrastructure abused by these campaigns is matched by *behaviour* patterns instead, never blocked by hostname:

- `api.anthropic.com/v1/api` — path-only detection (the host is legitimate, abused via a bogus path)
- `registry.npmjs.org` — the official npm registry; the worm's use of `/-/whoami` for token validation is what gets flagged
- `api.trongrid.io`, `fullnode.mainnet.aptoslabs.com`, `bsc-dataseed.binance.org`, `ip-api.com`, `temp.sh`, `check.torproject.org` — real services; flagged only when they appear alongside dynamic code execution or bulk upload
- Ethereum public RPC providers (`eth.llamarpc.com`, `eth.drpc.org`, `ethereum-rpc.publicnode.com`, `go.getblock.io`, …) — flagged only when the response feeds `eval`, `new Function()` or a spawn, which is the EtherHiding shape
- `workers.dev` (Cloudflare) and `github.com/oven-sh/bun/releases` — flagged on the specific subdomain shape and download behaviour, never on the host
- `api.telegram.org`, `hooks.zapier.com` — matched on the bot-API and catch-hook paths a dependency has no reason to call, not on the hostname

### 7. Integrity analysis
- Verification via `npm audit`
- Large JS file detection (>3MB)
- npm domain validation

## Report formats

### JSON
```json
{
  "scan_date": "2025-01-22T10:30:00",
  "project_path": "/path/to/project",
  "findings": [
    {
      "severity": "critical",
      "message": "KNOWN COMPROMISED PACKAGE",
      "location": "package.json",
      "details": {...}
    }
  ],
  "statistics": {
    "total_findings": 5,
    "critical": 2,
    "warning": 3
  }
}
```

### Markdown
Formatted report with tables and structured sections.

### Text
Plain text report for CI/CD integration.

## Notifications

### Webhook Configuration
Critical findings can be sent to a webhook:

```bash
./scan-npm-security.sh -w https://your-webhook-url
```

Payload format:
```json
{
  "text": "NPM Security Alert: X critical vulnerabilities",
  "findings": [...]
}
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: NPM Security Scan
  run: |
    python3 npm-supply-chain-detector.py . -o json -f scan-results.json
    if [ $? -ne 0 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

### GitLab CI
```yaml
npm-security-scan:
  script:
    - python3 npm-supply-chain-detector.py
  artifacts:
    reports:
      paths:
        - security-reports/
```

### Jenkins
```groovy
stage('Security Scan') {
    sh './scan-npm-security.sh -o json -f report.json'
}
```

## Custom configuration

Modify `malicious-patterns.json` to:

- Add new compromised packages
- Define custom patterns
- Adjust notification thresholds
- Exclude false positives

## Continuous monitoring

For 24/7 monitoring:

```bash
# With systemd
sudo tee /etc/systemd/system/npm-security-monitor.service << EOF
[Unit]
Description=NPM Security Monitor
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/project
ExecStart=/path/to/scan-npm-security.sh -c -i 600 -w https://webhook.url
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable npm-security-monitor
sudo systemctl start npm-security-monitor
```

## What to do when detection occurs?

1. **Critical findings**:
   - **Use quarantine mode**: `./scan-npm-security.sh --quarantine`
   - Immediately isolate compromised packages
   - Regenerate all exposed tokens/secrets (npm, GitHub, AWS, SSH keys)
   - Audit affected systems for credential exposure
   - Check for unauthorized GitHub repositories named "Shai-Hulud"
   - Review cloud metadata endpoint (IMDS) access logs

2. **CVE-2025-54313 specific**:
   - Check for malicious DLL/SO files (node-gyp.dll, loader.dll, etc.)
   - Scan for connections to C2 domains (firebase.su, dieorsuffer.com, smartscreen-api.com)
   - Windows systems: Review rundll32/regsvr32 execution logs

3. **Warnings**:
   - Investigate suspicious patterns
   - Verify package legitimacy before restoration
   - Update to safe versions
   - Review package maintainer changes

4. **Post-incident**:
   - Replace with safe package versions: `npm install <package>@<safe-version>`
   - `npm audit fix` for automatic fixes
   - Dependency review and lockfile verification
   - Set up continuous monitoring (`-c -i 300`)
   - Consider restoring from quarantine only after verification

## References

- [CrowdStrike NPM Attack 2025](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [CVE-2025-54313](https://nvd.nist.gov/vuln/detail/CVE-2025-54313)
- [CVE-2026-45321 (TanStack / Mini Shai-Hulud)](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [Mini Shai-Hulud SAP CAP (StepSecurity)](https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared)
- [Bitwarden CLI hijack (JFrog)](https://research.jfrog.com/post/bitwarden-cli-hijack/)
- [Shai-Hulud Miasma / Red Hat (Wiz)](https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages)
- [Shai-Hulud Hades PyPI wave (Socket)](https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave)
- [AntV ecosystem compromise (Socket)](https://socket.dev/blog/antv-packages-compromised)

June-July 2026 campaigns:

- [Mastra / easy-day-js (JFrog)](https://research.jfrog.com/post/easy-day-js/) · [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/)
- [Injective SDK backdoored (StepSecurity)](https://www.stepsecurity.io/blog/injective-npm-supply-chain-attack-18-packages-backdoored-to-steal-crypto-wallet-keys) · [Socket](https://socket.dev/blog/compromised-injective-sdk-npm-package)
- [IronWorm returns via jscrambler (JFrog)](https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/) · [Socket](https://socket.dev/blog/jscrambler-supply-chain-attack)
- [aone-cli RAT cluster targeting Alibaba developers (Socket)](https://socket.dev/blog/npm-rat-targets-alibaba)
- [Joyfill beta releases compromised (Socket)](https://socket.dev/blog/joyfill-npm-beta-releases-compromised) · [StepSecurity](https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise)

Miasma sub-waves, IronWorm and TrapDoor:

- [IronWorm, Shai-Hulud's "rustier cousin" (JFrog)](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/) · [SafeDep IOC feed](https://safedep.io/ti/campaigns/ironworm.json)
- [AsyncAPI compromised via GitHub Actions (StepSecurity)](https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm) · [Wiz](https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions)
- [TrapDoor crypto stealer poisoning AI instruction files (Socket)](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)
- [Hades/Miasma PyPI wave targeting bioinformatics and MCP developers (Socket)](https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious)
- [Miasma package list, machine-readable (Socket CSV)](https://socket.dev/api/public/supply-chain-attacks/miasma-mini-shai-hulud-supply-chain-attack/packages.csv)
- [OSSF malicious-packages feed (source of the OSV `MAL-*` records)](https://github.com/ossf/malicious-packages)

August 2026 — ChainDrop and Flooding Dropper:

- [ChainDrop npm worm, full IOC set (StepSecurity)](https://www.stepsecurity.io/blog/chaindrop-npm-worm)
- [ChainDrop: anatomy of a self-propagating worm (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/)
- [CHAINDROP hits 400+ npm packages (Elastic Security Labs)](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain)
- [keyv and cacheable hijacked (Wiz)](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack) · [Socket](https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain) · [Aikido](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack)
- [Worm compromises hundreds of npm packages, with a machine-readable package list (Datadog Security Labs)](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/)
- [Inside the keyv compromise: preinstall malware, trusted provenance, IDE hooks (Snyk)](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/)
- ['Flooding Dropper' hits npm with ~850 malicious packages (Sonatype, `sonatype-2026-005660`)](https://www.sonatype.com/blog/flooding-dropper-hits-npm-with-850-malicious-packages)
- [OSV bulk export — used to pull the complete, exact affected-version list for both campaigns](https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip)

- [npm audit documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)

## Notes

- **7499 compromised package versions** tracked across 3599 npm packages and 95 PyPI projects (updated 2026-08-06)
- **301 malware file hashes** detected (Shai-Hulud v1/v2 + Scavenger + the 2026 Mini Shai-Hulud, Miasma, IronWorm, ChainDrop and Flooding Dropper payloads)
- **Multiple attack campaigns** covered: CVE-2025-54313, Shai-Hulud v1/v2, the 2026 Mini Shai-Hulud / TeamPCP family (CVE-2026-45321), the June-July 2026 campaigns run by other actors, and the August 2026 ChainDrop and Flooding Dropper waves
- Scanner designed to minimize false positives. A domain match is reported as critical, so the list holds only hosts no honest dependency would contact; `registry.npmjs.org`, the blockchain RPC endpoints, `temp.sh`, `check.torproject.org` and `api.anthropic.com` are all matched by behaviour instead. Verified against legitimate `.claude`/`.vscode` configs, real `node-addon-api` build files, lockfiles with `resolved` URLs, ordinary development addresses (`127.0.0.1`, `0.0.0.0`, RFC1918), CalVer version numbers, an ACME client resolving DNS TXT records, and an optional-binary installer of the download/`chmod 0755`/spawn kind that esbuild and sharp use
- Patterns based on real observed attacks (July 2025 - July 2026)
- Regular update of malicious patterns recommended
- Compatible with all standard NPM projects
- Quarantine feature allows safe isolation with restoration option

## Limitations

- Does not replace thorough manual analysis
- May not detect zero-day attacks
- Performance dependent on project size
- Requires read permissions on node_modules

## False-positive testing

Detection rules are measured against real code, not only against synthetic samples. Two corpora are used:

- **44 popular, uncompromised npm packages** downloaded straight from the registry (express, lodash, axios, esbuild, sharp, webpack, typescript, eslint, ws, undici, acme-client, bcrypt…). The expected result is **zero findings**.
- **Fixtures** pairing every rule with the legitimate construct it could be confused with: an optional-binary installer of the download/`chmod 0755`/spawn kind, a `node-addon-api` build file, `python3 -c` header lookups, an ACME client resolving DNS TXT records, CalVer version numbers, the clean neighbouring releases of `chalk` and `debug`, and ordinary development addresses.

That exercise found and removed four rules that fired on ordinary code: an ungrouped alternation that collapsed to the bare word `spawn`, another that collapsed to `net.connect`, `npm publish --access public` (the standard release command for any scoped package), and `process.env.<X>` followed by `fetch(` — which is what every API SDK does, and which matched almost any minified bundle. Each was replaced by the narrower shape that carries the actual signal: the environment being serialised *whole* and sent, `npm publish` invoked from code, a connection to a hardcoded *public* address, and the scanner being run or downloaded rather than merely mentioned.

## Contributing

To add new patterns or compromised packages:

1. **Update pattern files:**
   - Edit `update-patterns.py` to add new packages/patterns
   - Run `python3 update-patterns.py` to regenerate `shai-hulud-iocs.json` **and** sync `malicious-patterns.json` (packages, code patterns, C2 domains)
   - Avoid editing the JSON files by hand — manual edits are overwritten on the next regeneration

2. **Test changes:**
   ```bash
   python3 npm-supply-chain-detector.py -v test-project/
   ```

3. **Update documentation:**
   - Update statistics in `README.md`
