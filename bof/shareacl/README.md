# shareacl BOF

Beacon Object File that enumerates SMB share-level ACLs under the current
Beacon token/context and emits structured JSON for SPOTTER / Flowsint ingestion.

## Python port

The same output contract is also available as a cross-platform Python script at
[scripts/shareacl.py](../../scripts/shareacl.py). It emits the same
`[shareacl]` JSON lines and writes `shareacl_results.txt` in the current
working directory, so `shareacl_normalizer.py` can consume either source
without changes.

Python usage requires explicit authentication values (`--username`,
`--password`, `--domain`) for SMB/LDAP operations:

```bash
python3 scripts/shareacl.py FILESERVER --username operator --password 'Secret123!' --domain CORP
python3 scripts/shareacl.py \\FILESERVER\Finance$ --username operator --password 'Secret123!' --domain CORP
python3 scripts/shareacl.py --computers --dc dc01.corp.local --username operator --password 'Secret123!' --domain CORP
python3 scripts/shareacl.py --computers --dc dc01.corp.local --ldaps --username operator --password 'Secret123!' --domain CORP
```

`--computers` mode queries Active Directory (LDAP) for enabled computer
objects, then scans each host over SMB. Add `--ldaps` to force secure LDAP
transport on port 636.

## Usage

```text
beacon> shareacl FILESERVER
beacon> shareacl \\FILESERVER\Finance$
beacon> shareacl --computers
beacon> shareacl --computers --ldaps
```

`--computers` discovers enabled Active Directory computer objects and runs the
share/ACL enumeration against each host.  The BOF outputs one JSON object per
share, prefixed with `[shareacl]`, to the Beacon console **and** to a local
results file (see below):

Use `--ldaps` with `--computers` when the domain controller requires secure
LDAP.

The BOF also emits verbose operator-facing status lines (for example host/share
progress and LDAP discovery steps). These status lines are plain `shareacl:`
console messages and do **not** use the `[shareacl]` prefix, so existing
normalization pipelines remain unchanged.

```text
[shareacl] {"host":"FILESERVER","share_name":"Finance$","unc_path":"\\\\fileserver\\finance$","is_hidden":true,"share_type":"DISK","source":"shareacl_bof","error_code":null,"acls":[{"trustee_sid":"S-1-1-0","trustee_name":"Everyone","trustee_domain":"","trustee_type":"WellKnownGroup","access_mask":1179817,"access_mask_hex":"\"0x1200A9\"","ace_type":"ACCESS_ALLOWED","rights":["READ"],"effective_access":"READ"}]}
```

## Build

```bash
make
```

Produces `shareacl.x64.o` and `shareacl.x86.o`, which are gitignored build
output rather than shipped artefacts. Requires the mingw-w64 toolchain:

```bash
# Debian/Ubuntu
sudo apt install mingw-w64

# macOS
brew install mingw-w64
```

## Cobalt Strike integration

Run `make` first (see Build above): the object files are build output and are
not in the repo, and `shareacl.cna` resolves them at load time via
`script_resource()`, so Script Manager fails on a fresh clone without them.

Then load `shareacl.cna` in Cobalt Strike (Script Manager). It registers the
`shareacl` command and executes the correct architecture object file.

## Local results file

Every `[shareacl]` line is also written to `shareacl_results.txt` in the
Beacon's **current working directory** on the target host (a fresh file is
created on each run; the operator is told the full path in the console). The
file contains the exact same prefixed lines as the console, so it is directly
consumable by `shareacl_normalizer.py` without any editing.

> Operational note: this drops a file on the target's disk. Retrieve it with
> Beacon's `download`, then remove it (`rm` / `del`) as part of engagement
> cleanup.

## SPOTTER / Flowsint integration

1. Retrieve the results file the BOF wrote on the target:

   ```text
   beacon> download shareacl_results.txt
   ```

2. Convert the output to a Flowsint batch import:

   ```bash
   cd /data/scripts
   python shareacl_normalizer.py /path/to/shareacl_results.txt > shareacl-batch.json
   ```

3. Import via `flowsint_client.batch_import` or through the n8n workflow chain.

## Output schema

Each share line is a JSON object containing:

- `host`, `share_name`, `unc_path`, `is_hidden`, `share_type`
- `acls`: array of ACE records with `trustee_sid`, `trustee_name`,
  `trustee_domain`, `trustee_type`, `access_mask`, `access_mask_hex`,
  `ace_type`, `rights`, and `effective_access`.

The normalizer converts trustees to `Individual` / `Group` / `Computer` nodes
and creates permission-specific edges such as `SHARE_READ`, `SHARE_WRITE`,
`SHARE_FULL`, `SHARE_EXECUTE`, `SHARE_DENY`, and `SHARE_CUSTOM`.

When `--computers` is used, two additional event lines are emitted:
`ad_computers_found` (total enabled computers returned by LDAP) and
`ad_computers_done` (how many were successfully contacted).

## Files

| File | Purpose |
|------|---------|
| `shareacl.c` | BOF source code (includes LDAP computer discovery) |
| `beacon.h` | Minimal Beacon API declarations |
| `Makefile` | Cross-compile x64/x86 object files |
| `shareacl.cna` | Cobalt Strike Aggressor script |
| `../../scripts/shareacl_normalizer.py` | Convert BOF output to Flowsint nodes/edges |
| `../../flowsint-custom/enrichers/share_acl_enricher.py` | Enrich FileShare nodes from `HAS_PERMISSION` edges |

## Safe-use constraints

- Authorized red-team / penetration-test engagements only.
- Read-only enumeration; no share or ACL modifications are made.
- All queries run under the current Windows user context of the Beacon.
