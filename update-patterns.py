#!/usr/bin/env python3


import json

compromised_packages = {
    "@ahmedhfarag/ngx-perfect-scrollbar": ["20.0.20"],
    "@ahmedhfarag/ngx-virtual-scroller": ["4.0.4"],
    "@art-ws/common": ["2.0.28"],
    "@art-ws/config-eslint": ["2.0.4", "2.0.5"],
    "@art-ws/config-ts": ["2.0.7", "2.0.8"],
    "@art-ws/db-context": ["2.0.24"],
    "@art-ws/di-node": ["2.0.13"],
    "@art-ws/di": ["2.0.28", "2.0.32"],
    "@art-ws/eslint": ["1.0.5", "1.0.6"],
    "@art-ws/fastify-http-server": ["2.0.24", "2.0.27"],
    "@art-ws/http-server": ["2.0.21", "2.0.25"],
    "@art-ws/openapi": ["0.1.12", "0.1.9"],
    "@art-ws/package-base": ["1.0.5", "1.0.6"],
    "@art-ws/prettier": ["1.0.5", "1.0.6"],
    "@art-ws/slf": ["2.0.15", "2.0.22"],
    "@art-ws/ssl-info": ["1.0.10", "1.0.9"],
    "@art-ws/web-app": ["1.0.3", "1.0.4"],
    "@crowdstrike/commitlint": ["8.1.1", "8.1.2"],
    "@crowdstrike/falcon-shoelace": ["0.4.1", "0.4.2"],
    "@crowdstrike/foundry-js": ["0.19.1", "0.19.2"],
    "@crowdstrike/glide-core": ["0.34.2", "0.34.3"],
    "@crowdstrike/logscale-dashboard": ["1.205.1", "1.205.2"],
    "@crowdstrike/logscale-file-editor": ["1.205.1", "1.205.2"],
    "@crowdstrike/logscale-parser-edit": ["1.205.1", "1.205.2"],
    "@crowdstrike/logscale-search": ["1.205.1", "1.205.2"],
    "@crowdstrike/tailwind-toucan-base": ["5.0.1", "5.0.2"],
    "@ctrl/deluge": ["7.2.1", "7.2.2"],
    "@ctrl/golang-template": ["1.4.2", "1.4.3"],
    "@ctrl/magnet-link": ["4.0.3", "4.0.4"],
    "@ctrl/ngx-codemirror": ["7.0.1", "7.0.2"],
    "@ctrl/ngx-csv": ["6.0.1", "6.0.2"],
    "@ctrl/ngx-emoji-mart": ["9.2.1", "9.2.2"],
    "@ctrl/ngx-rightclick": ["4.0.1", "4.0.2"],
    "@ctrl/qbittorrent": ["9.7.1", "9.7.2"],
    "@ctrl/react-adsense": ["2.0.1", "2.0.2"],
    "@ctrl/shared-torrent": ["6.3.1", "6.3.2"],
    "@ctrl/tinycolor": ["4.1.1", "4.1.2"],
    "@ctrl/torrent-file": ["4.1.1", "4.1.2"],
    "@ctrl/transmission": ["7.3.1"],
    "@ctrl/ts-base32": ["4.0.1", "4.0.2"],
    "@hestjs/core": ["0.2.1"],
    "@hestjs/cqrs": ["0.1.6"],
    "@hestjs/demo": ["0.1.2"],
    "@hestjs/eslint-config": ["0.1.2"],
    "@hestjs/logger": ["0.1.6"],
    "@hestjs/scalar": ["0.1.7"],
    "@hestjs/validation": ["0.1.6"],
    "@nativescript-community/arraybuffers": ["1.1.6", "1.1.7", "1.1.8"],
    "@nativescript-community/gesturehandler": ["2.0.35"],
    "@nativescript-community/perms": ["3.0.5", "3.0.6", "3.0.7", "3.0.8", "3.0.9"],
    "@nativescript-community/sentry": ["4.6.43"],
    "@nativescript-community/sqlite": ["3.5.2", "3.5.3", "3.5.4", "3.5.5"],
    "@nativescript-community/text": ["1.6.10", "1.6.11", "1.6.12", "1.6.13", "1.6.9"],
    "@nativescript-community/typeorm": ["0.2.30", "0.2.31", "0.2.32", "0.2.33"],
    "@nativescript-community/ui-collectionview": ["6.0.6"],
    "@nativescript-community/ui-document-picker": ["1.1.27", "1.1.28"],
    "@nativescript-community/ui-drawer": ["0.1.30"],
    "@nativescript-community/ui-image": ["4.5.6"],
    "@nativescript-community/ui-label": ["1.3.35", "1.3.36", "1.3.37"],
    "@nativescript-community/ui-material-bottom-navigation": ["7.2.72", "7.2.73", "7.2.74", "7.2.75"],
    "@nativescript-community/ui-material-bottomsheet": ["7.2.72"],
    "@nativescript-community/ui-material-core-tabs": ["7.2.72", "7.2.73", "7.2.74", "7.2.75", "7.2.76"],
    "@nativescript-community/ui-material-core": ["7.2.72", "7.2.73", "7.2.74", "7.2.75", "7.2.76"],
    "@nativescript-community/ui-material-ripple": ["7.2.72", "7.2.73", "7.2.74", "7.2.75"],
    "@nativescript-community/ui-material-tabs": ["7.2.72", "7.2.73", "7.2.74", "7.2.75"],
    "@nativescript-community/ui-pager": ["14.1.36", "14.1.37", "14.1.38"],
    "@nativescript-community/ui-pulltorefresh": ["2.5.4", "2.5.5", "2.5.6", "2.5.7"],
    "@nexe/config-manager": ["0.1.1"],
    "@nexe/eslint-config": ["0.1.1"],
    "@nexe/logger": ["0.1.3"],
    "@nstudio/angular": ["20.0.4", "20.0.5", "20.0.6"],
    "@nstudio/focus": ["20.0.4", "20.0.5", "20.0.6"],
    "@nstudio/nativescript-checkbox": ["2.0.6", "2.0.7", "2.0.8", "2.0.9"],
    "@nstudio/nativescript-loading-indicator": ["5.0.1", "5.0.2", "5.0.3", "5.0.4"],
    "@nstudio/ui-collectionview": ["5.1.11", "5.1.12", "5.1.13", "5.1.14"],
    "@nstudio/web-angular": ["20.0.4"],
    "@nstudio/web": ["20.0.4"],
    "@nstudio/xplat-utils": ["20.0.5", "20.0.6", "20.0.7"],
    "@nstudio/xplat": ["20.0.5", "20.0.6", "20.0.7"],
    "@rxap/ngx-bootstrap": ["19.0.3", "19.0.4"],
    "@teriyakibomb/ember-velcro": ["2.2.1"],
    "@teselagen/bio-parsers": ["0.4.30"],
    "@teselagen/bounce-loader": ["0.3.16", "0.3.17"],
    "@teselagen/file-utils": ["0.3.22"],
    "@teselagen/liquibase-tools": ["0.4.1"],
    "@teselagen/ove": ["0.7.40"],
    "@teselagen/range-utils": ["0.3.14", "0.3.15"],
    "@teselagen/react-list": ["0.8.19", "0.8.20"],
    "@teselagen/react-table": ["6.10.19", "6.10.20", "6.10.22"],
    "@teselagen/sequence-utils": ["0.3.34"],
    "@teselagen/ui": ["0.9.10"],
    "@thangved/callback-window": ["1.1.4"],
    "@tnf-dev/api": ["1.0.8"],
    "@tnf-dev/core": ["1.0.8"],
    "@tnf-dev/js": ["1.0.8"],
    "@tnf-dev/mui": ["1.0.8"],
    "@tnf-dev/react": ["1.0.8"],
    "@ui-ux-gang/devextreme-angular-rpk": ["24.1.7"],
    "@yoobic/design-system": ["6.5.17"],
    "@yoobic/jpeg-camera-es6": ["1.0.13"],
    "@yoobic/yobi": ["8.7.53"],
    "airchief": ["0.3.1"],
    "airpilot": ["0.8.8"],
    "angulartics2": ["14.1.1", "14.1.2"],
    "another-shai": ["1.0.1"],
    "browser-webdriver-downloader": ["3.0.8"],
    "capacitor-notificationhandler": ["0.0.2", "0.0.3"],
    "capacitor-plugin-healthapp": ["0.0.2", "0.0.3"],
    "capacitor-plugin-ihealth": ["1.1.8", "1.1.9"],
    "capacitor-plugin-vonage": ["1.0.2", "1.0.3"],
    "capacitorandroidpermissions": ["0.0.4", "0.0.5"],
    "config-cordova": ["0.8.5"],
    "cordova-plugin-voxeet2": ["1.0.24"],
    "cordova-voxeet": ["1.0.32"],
    "create-hest-app": ["0.1.9"],
    "db-evo": ["1.1.4", "1.1.5"],
    "devextreme-angular-rpk": ["21.2.8"],
    "ember-browser-services": ["5.0.2", "5.0.3"],
    "ember-headless-form-yup": ["1.0.1"],
    "ember-headless-form": ["1.1.2", "1.1.3"],
    "ember-headless-table": ["2.1.5", "2.1.6"],
    "ember-url-hash-polyfill": ["1.0.12", "1.0.13"],
    "ember-velcro": ["2.2.1", "2.2.2"],
    "encounter-playground": ["0.0.2", "0.0.3", "0.0.4", "0.0.5"],
    "eslint-config-crowdstrike-node": ["4.0.3", "4.0.4"],
    "eslint-config-crowdstrike": ["11.0.2", "11.0.3"],
    "eslint-config-teselagen": ["6.1.7", "6.1.8"],
    "globalize-rpk": ["1.7.4"],
    "graphql-sequelize-teselagen": ["5.3.8", "5.3.9"],
    "html-to-base64-image": ["1.0.2"],
    "json-rules-engine-simplified": ["0.2.1", "0.2.4"],
    "jumpgate": ["0.0.2"],
    "koa2-swagger-ui": ["5.11.1", "5.11.2"],
    "mcfly-semantic-release": ["1.3.1"],
    "mcp-knowledge-base": ["0.0.2"],
    "mcp-knowledge-graph": ["1.2.1"],
    "mobioffice-cli": ["1.0.3"],
    "monorepo-next": ["13.0.1", "13.0.2"],
    "mstate-angular": ["0.4.4"],
    "mstate-cli": ["0.4.7"],
    "mstate-dev-react": ["1.1.1"],
    "mstate-react": ["1.6.5"],
    "ng2-file-upload": ["7.0.2", "7.0.3", "8.0.1", "8.0.2", "8.0.3", "9.0.1"],
    "ngx-bootstrap": ["18.1.4", "19.0.3", "19.0.4", "20.0.3", "20.0.4", "20.0.5"],
    "ngx-color": ["10.0.1", "10.0.2"],
    "ngx-toastr": ["19.0.1", "19.0.2"],
    "ngx-trend": ["8.0.1"],
    "ngx-ws": ["1.1.5", "1.1.6"],
    "oradm-to-gql": ["35.0.14", "35.0.15"],
    "oradm-to-sqlz": ["1.1.2"],
    "ove-auto-annotate": ["0.0.10", "0.0.9"],
    "pm2-gelf-json": ["1.0.4", "1.0.5"],
    "printjs-rpk": ["1.6.1"],
    "react-complaint-image": ["0.0.32", "0.0.35"],
    "react-jsonschema-form-conditionals": ["0.3.18", "0.3.21"],
    "react-jsonschema-form-extras": ["1.0.4"],
    "react-jsonschema-rxnt-extras": ["0.4.9"],
    "remark-preset-lint-crowdstrike": ["4.0.1", "4.0.2"],
    "rxnt-authentication": ["0.0.3", "0.0.4", "0.0.5", "0.0.6"],
    "rxnt-healthchecks-nestjs": ["1.0.2", "1.0.3", "1.0.4", "1.0.5"],
    "rxnt-kue": ["1.0.4", "1.0.5", "1.0.6", "1.0.7"],
    "swc-plugin-component-annotate": ["1.9.1", "1.9.2"],
    "tbssnch": ["1.0.2"],
    "teselagen-interval-tree": ["1.1.2"],
    "tg-client-query-builder": ["2.14.4", "2.14.5"],
    "tg-redbird": ["1.3.1", "1.3.2"],
    "tg-seq-gen": ["1.0.10", "1.0.9"],
    "thangved-react-grid": ["1.0.3"],
    "ts-gaussian": ["3.0.5", "3.0.6"],
    "ts-imports": ["1.0.1", "1.0.2"],
    "tvi-cli": ["0.1.5"],
    "ve-bamreader": ["0.2.6", "0.2.7"],
    "ve-editor": ["1.0.1", "1.0.2"],
    "verror-extra": ["6.0.1"],
    "voip-callkit": ["1.0.2", "1.0.3"],
    "wdio-web-reporter": ["0.1.3"],
    "yargs-help-output": ["5.0.3"],
    "yoo-styles": ["6.0.326"]
}

# @operato and @things-factory
operato_packages = {
    "@operato/board": ["9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51"],
    "@operato/data-grist": ["9.0.29", "9.0.35", "9.0.36", "9.0.37"],
    "@operato/graphql": ["9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51"],
    "@operato/headroom": ["9.0.2", "9.0.35", "9.0.36", "9.0.37"],
    "@operato/help": ["9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51"],
    "@operato/i18n": ["9.0.35", "9.0.36", "9.0.37"],
    "@operato/input": ["9.0.27", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48"],
    "@operato/layout": ["9.0.35", "9.0.36", "9.0.37"],
    "@operato/popup": ["9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51"],
    "@operato/pull-to-refresh": ["9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47"],
    "@operato/shell": ["9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39"],
    "@operato/styles": ["9.0.2", "9.0.35", "9.0.36", "9.0.37"],
    "@operato/utils": ["9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51"]
}

things_factory_packages = {
    "@things-factory/attachment-base": ["9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51", "9.0.52", "9.0.53", "9.0.54", "9.0.55"],
    "@things-factory/auth-base": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"],
    "@things-factory/email-base": ["9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51", "9.0.52", "9.0.53", "9.0.54", "9.0.55", "9.0.56", "9.0.57", "9.0.58", "9.0.59"],
    "@things-factory/env": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"],
    "@things-factory/integration-base": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"],
    "@things-factory/integration-marketplace": ["9.0.43", "9.0.44", "9.0.45"],
    "@things-factory/shell": ["9.0.42", "9.0.43", "9.0.44", "9.0.45"]
}

compromised_packages.update(operato_packages)
compromised_packages.update(things_factory_packages)

# Hash SHA-256 bundle.js
bundle_hashes = {
    "version_1": "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
    "version_2": "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
    "version_3": "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
    "version_4": "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "version_5": "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "version_6": "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "version_7": "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"
}

iocs = {
    "exfiltration_webhook": "webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
    "github_workflow_files": ["shai-hulud.yaml", "shai-hulud-workflow.yml"],
    "github_repo_name": "Shai-Hulud",
    "github_migration_repos": "Shai-Hulud Migration",
    "malicious_script": "bundle.js",
    "postinstall_hook": "postInstall"
}

additional_patterns = [
    # Patterns spécifiques aux versions
    (r'shai-hulud\.yaml|shai-hulud-workflow\.yml', "Shai-Hulud workflow file detected", "critical"),
    (r'Shai-Hulud.*Migration', "Shai-Hulud migration repository pattern", "critical"),
    (r'webhook\.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7', "Known Shai-Hulud exfiltration endpoint", "critical"),
    
    # Patterns de reconnaissance
    (r'npm.*whoami', "NPM identity reconnaissance", "warning"),
    (r'npm.*token.*list', "NPM token enumeration", "critical"),
    (r'GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY', "Credential environment variable access", "critical"),
    (r'process\.env\.NODE_AUTH_TOKEN|AZURE_CLIENT_SECRET', "Cloud credential access", "critical"),
    
    # Patterns de propagation
    (r'fs.*writeFileSync.*package\.json', "Package.json modification attempt", "critical"),
    (r'child_process.*npm.*init', "NPM package initialization", "warning"),
    (r'glob.*node_modules.*package\.json', "Node modules scanning", "warning"),
    
    # Patterns Git
    (r'git config --unset core\.bare', "Git repository manipulation", "critical"),
    (r'rm -rf \.github/workflows', "GitHub workflows deletion", "critical"),
    (r'git.*mirror.*clone', "Git mirror operations", "warning"),
    
    # Cloud metadata
    (r'169\.254\.169\.254', "AWS metadata endpoint access", "critical"),
    (r'metadata\.google\.internal', "GCP metadata endpoint access", "critical"),
    (r'metadata\.azure\.com', "Azure metadata endpoint access", "critical")
]

updated_patterns = {
    "known_compromised_packages": compromised_packages,
    "bundle_js_hashes": bundle_hashes,
    "indicators_of_compromise": iocs,
    "malicious_code_patterns": additional_patterns,
    "attack_timeline": {
        "2025-09-14": "First observed compromise (17:58 UTC)",
        "2025-09-15": "Multiple bursts, 100+ packages compromised",
        "2025-09-16": "CrowdStrike packages compromised (01:14 UTC)"
    },
    "total_compromised_count": 526
}

with open("shai-hulud-iocs.json", "w") as f:
    json.dump(updated_patterns, f, indent=2)

print(f"File Created : shai-hulud-iocs.json")
print(f"Total packets compromised : {len(compromised_packages)}")
print(f"Hash bundle.js: {len(bundle_hashes)} versions")
print(f"Additional patterns: {len(additional_patterns)}")

# --- PATCH APPEND (2025-09-22) ---
# This block only ADDS lines. It does not remove/modify earlier content.
# Purpose: incorporate newly reported items from JFrog / Unit42 / Sonatype (Shai-Hulud npm worm).
# Sources: JFrog (Sep 16 2025) shows @basic-ui-components-stc/basic-ui-components@1.0.5 as compromised.
# - We also extend @art-ws/db-context with version 2.0.21 (seen in JFrog's extended list).
# - Patterns expanded for additional token env vars and GitHub workflow variants.

compromised_packages.update({
    "@basic-ui-components-stc/basic-ui-components": ["1.0.5"],  # JFrog newly detected
})

compromised_packages.setdefault("@art-ws/db-context", [])
if "2.0.21" not in compromised_packages["@art-ws/db-context"]:
    compromised_packages["@art-ws/db-context"].append("2.0.21")

if isinstance(iocs, dict):
    iocs.setdefault("github_workflow_branch", "shai-hulud") 
    iocs.setdefault("repo_created_name", "Shai-Hulud")    

try:
    additional_patterns.extend([
        (r'GH_TOKEN|GITLAB_TOKEN|BITBUCKET_TOKEN', "Common VCS token env vars possibly exfiltrated", "warning"),
        (r'GITHUB_APP_TOKEN|GH_PAT', "GitHub App or Personal Access Token env vars", "warning"),
        (r'\.github/workflows/shai-hulud-.*\.yml', "Shai-Hulud workflow variant file", "critical"),
        (r'makeRepo\("Shai-Hulud"', "GitHub repo creation function name seen in payload", "warning"),
    ])
except NameError:
    pass

try:
    updated_patterns["attack_timeline"]["2025-09-18"] = "Reports exceed 500 compromised packages (Truesec / others)"
except Exception:
    pass

try:
    updated_patterns["known_compromised_packages"] = compromised_packages
    updated_patterns["indicators_of_compromise"] = iocs
    updated_patterns["malicious_code_patterns"] = additional_patterns
    updated_patterns["total_compromised_count"] = len(compromised_packages)
    with open("shai-hulud-iocs.json", "w") as f:
        json.dump(updated_patterns, f, indent=2)
except Exception:
    pass

print("Patch-append block executed: new packages/patterns added and JSON rewritten.")

# --- PATCH APPEND FIX (2025-09-22) ---
# Ensure total_compromised_count equals the TOTAL NUMBER OF VERSIONS,
# not just the number of package families.
try:
    _patterns_list = None
    for _name in ("malicious_code_patterns", "additional_patterns", "patterns", "rules"):
        try:
            _patterns_list = globals().get(_name, None)
            if isinstance(_patterns_list, list):
                break
        except Exception:
            pass

    _total_versions = 0
    if isinstance(compromised_packages, dict):
        _total_versions = sum(len(set(v if isinstance(v, list) else [v])) for v in compromised_packages.values())

    _json_out = {
        "known_compromised_packages": compromised_packages,
        "indicators_of_compromise": iocs if 'iocs' in globals() else {},
        "malicious_code_patterns": _patterns_list if isinstance(_patterns_list, list) else [],
    }

    if 'bundle_hashes' in globals():
        _json_out["bundle_js_hashes"] = bundle_hashes

    if 'attack_timeline' in globals():
        _json_out["attack_timeline"] = attack_timeline

    _json_out["total_compromised_count"] = _total_versions

    import json as _json
    with open("shai-hulud-iocs.json", "w") as _f:
        _json.dump(_json_out, _f, indent=2)

    print(f"Fix-append block executed: total_compromised_count set to versions total = {_total_versions}")
except Exception as _e:
    print("Fix-append block error:", _e)
