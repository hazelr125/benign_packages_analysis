# Benign Packages Analysis

This repository builds a structured analysis dataset from benign npm and PyPI packages. It downloads selected package metadata and source files, compiles packages into compressed dataset shards, extracts static metadata features, and creates focused code-context records for potentially high-risk APIs.

The pipeline is designed for large-scale package analysis while keeping storage and downstream model inputs manageable. It uses two analysis tiers:

- **Tier 1 — metadata and lexical features:** compact, mostly numeric package-level features.
- **Tier 2 — code chunks:** focused source-code context surrounding calls to APIs or patterns that may deserve further inspection.

> **Important:** The scripts use Google Colab/Google Drive paths under `/content/drive/MyDrive/SHIELD_DATA`. They expect to be run in an environment where that directory is available, or to be edited for another storage location.

## Repository contents

### `pull_benign_registry.py`

Downloads the latest available versions of benign packages from npm and PyPI and preserves only files considered important for the analysis pipeline.

#### Why it exists

Downloading complete package archives can consume substantial disk space. This script reduces storage requirements by retaining only files that are useful for Tier 1 metadata extraction and Tier 2 code inspection.

#### Inputs

For each ecosystem, it expects a seed list at:

- `data/seed_lists/npm_benign_seeds.json`
- `data/seed_lists/pypi_benign_seeds.json`

Each seed file is expected to contain a JSON array of package names, for example:

```json
["lodash", "chalk", "requests"]
```

The script does not create these seed lists. They must already exist.

#### What it downloads

- **npm:** package metadata from `registry.npmjs.org`, followed by the tarball for the version tagged `latest`.
- **PyPI:** package metadata from `pypi.org`, followed by the newest release file, preferring a source distribution (`sdist`) over a wheel.

#### Files preserved from package archives

Only files whose base name matches one of these names are extracted:

- `package.json`
- `setup.py`
- `setup.cfg`
- `pyproject.toml`
- `preinstall.js`
- `postinstall.js`
- `index.js`
- `__init__.py`

The files are written below:

```text
/content/drive/MyDrive/SHIELD_DATA/raw_store/benign/
├── npm/<package-name>/<version>/
└── pypi/<package-name>/<version>/
```

#### Output

The primary output is the selective raw package store. When using `extractor.py`, failed downloads are also recorded as:

```text
/content/drive/MyDrive/SHIELD_DATA/raw_store/benign/npm_failed_ingestion.json
/content/drive/MyDrive/SHIELD_DATA/raw_store/benign/pypi_failed_ingestion.json
```

Each failure-log element is an object with this structure:

```json
{
  "name": "package-name",
  "error": "HTTP 404"
}
```

The failure log is produced by `extractor.py`; the current `pull_benign_registry.py` implementation reports failures to the console but does not write the JSON failure log.

#### Execution

Running the file directly processes both ecosystems with 12 worker threads:

```bash
python pull_benign_registry.py
```

---

### `extractor.py`

Downloads and selectively extracts the latest npm and PyPI packages, using concurrent HTTP requests and connection pooling.

#### Why it exists

This is the more complete ingestion implementation. In addition to preserving selected package files, it records failed packages so that ingestion can be retried or audited later.

#### Main behavior

1. Reads an ecosystem-specific seed list.
2. Creates a reusable `requests.Session` with an HTTP connection pool.
3. Fetches packages concurrently with `ThreadPoolExecutor`.
4. Extracts only the target metadata and entry-point files.
5. Counts successes and failures.
6. Writes failed package names and error messages to a JSON log.

#### Output directory structure

Successful packages are stored as:

```text
/content/drive/MyDrive/SHIELD_DATA/raw_store/benign/
├── npm/<package-name>/<version>/<selected-files>
└── pypi/<package-name>/<version>/<selected-files>
```

#### Failure-log data structure

The failure log is a JSON array. Each element is an object with two string fields:

```json
[
  {
    "name": "example-package",
    "error": "Download failed: 404"
  }
]
```

#### Execution

```bash
python extractor.py
```

This runs npm and PyPI ingestion with 12 workers per ecosystem. `pull_benign_registry.py` and `extractor.py` overlap substantially; use one ingestion script rather than running both unless duplicate downloading is intentional.

---

### `compile_dataset.py`

Finds package roots in the raw store, writes them into compressed tar shards, and generates a unified Parquet manifest describing every package.

#### Why it exists

A large collection of individual package directories is inconvenient to move, index, or process. This script creates bounded-size archives and a manifest that provides package-level coordinates and labels.

#### Inputs

It scans:

```text
/content/drive/MyDrive/SHIELD_DATA/raw_store/
├── benign/
└── malicious/
```

A directory is treated as a package root when it contains at least one of:

- `package.json`
- `setup.py`
- `pyproject.toml`
- `setup.cfg`

The package is classified as npm when `package.json` is present; otherwise it is classified as PyPI.

#### Shard output

Compressed shards are written to:

```text
/content/drive/MyDrive/SHIELD_DATA/shards/
```

Shard names have this format:

```text
shield_shard_001.tar.zst
shield_shard_002.tar.zst
...
```

The target maximum uncompressed payload per shard is 2 GiB. Shard sizes are tracked approximately using the sum of contained file sizes; tar headers and compression effects are not included in that calculation.

#### Manifest output

The manifest is written to:

```text
/content/drive/MyDrive/SHIELD_DATA/manifest.parquet
```

It is a pandas/Apache Parquet table compressed with Snappy. Each row describes one package.

#### Manifest data structure

The manifest contains these columns:

| Column | Type / values | Meaning |
|---|---|---|
| `uid` | string | First 16 hexadecimal characters of the SHA-256 hash of `package_rel_path`; serves as a stable package identifier within this dataset layout. |
| `ecosystem` | string: `npm` or `pypi` | Package ecosystem inferred from package metadata files. |
| `label` | integer: `1` or `0` | `1` for packages under `malicious/`; `0` for packages under `benign/`. |
| `source_collection` | string | Name of the collection directory containing the package. |
| `package_rel_path` | string | Package path relative to `SHIELD_DATA/raw_store`, such as `benign/npm/example/1.0.0`. |
| `shard_id` | string | Name of the compressed shard containing the package. |
| `uncompressed_offset` | integer | Approximate uncompressed byte offset at which the package was added to its shard. |
| `size_bytes` | integer | Approximate total size of the package files before compression. |
| `has_install_script` | boolean | Set based on whether `setup.py` or `package.json` is present. Despite its name, this currently indicates package metadata presence rather than proving that an install hook exists. |

Duplicate rows with the same `package_rel_path` are removed before the manifest is saved.

#### Execution

```bash
python compile_dataset.py
```

---

### `extract_tier1_features.py`

Extracts compact metadata, dependency, lifecycle, author, and package-name similarity features from the manifest and selected package files.

#### Why it exists

Tier 1 provides inexpensive, tabular signals that can be used for exploratory analysis, statistical comparisons, or machine-learning models without passing full source code to a downstream system.

#### Inputs

- `manifest.parquet`
- The package directories referenced by each manifest row
- `package.json` for npm packages
- `setup.py` and optionally `PKG-INFO` for PyPI packages

#### Feature extraction behavior

For npm packages, the script parses `package.json` and extracts description, README, author, homepage/repository, dependency, development-dependency, and lifecycle-script information.

For PyPI packages, it parses `setup.py` using Python's AST module without executing the file. It detects description length, homepage metadata, authors, dependencies, and custom `cmdclass` definitions. If needed, it uses `PKG-INFO` as a fallback for summary, homepage, and author information.

It also computes package-name similarity against predefined canonical package lists using:

- Minimum Levenshtein distance.
- Maximum Jaro-Winkler similarity.

These features can help identify names that are unusually close to popular packages, although they are not by themselves proof of typosquatting or malicious behavior.

#### Output

The output is written to:

```text
/content/drive/MyDrive/SHIELD_DATA/tier1_features.parquet
```

It is a Snappy-compressed Parquet table with one row per manifest record.

#### Tier 1 output data structure

| Column | Type / values | Meaning |
|---|---|---|
| `uid` | string | Package identifier copied from the manifest. |
| `ecosystem` | integer: `1` for npm, `0` for PyPI | Numeric ecosystem encoding. |
| `label` | integer: `1` or `0` | Package label copied from the manifest. |
| `desc_len` | integer | Length of the package description or summary. |
| `has_readme` | integer: `0` or `1` | Whether npm metadata contains a README value. |
| `author_count` | integer | Number of authors/maintainers detected. |
| `has_homepage` | integer: `0` or `1` | Whether homepage, repository, project URL, or equivalent metadata was detected. |
| `dep_count` | integer | Number of runtime dependencies detected. |
| `dev_dep_count` | integer | Number of npm development dependencies detected. For PyPI rows this normally remains `0`. |
| `has_preinstall` | integer: `0` or `1` | Whether an npm `preinstall` script was detected. |
| `has_postinstall` | integer: `0` or `1` | Whether an npm `postinstall` or `install` script was detected. |
| `has_cmdclass` | integer: `0` or `1` | Whether a PyPI `setup.py` custom `cmdclass` was detected. |
| `min_levenshtein` | integer | Minimum edit distance from the package name to the relevant canonical package list. |
| `max_jaro_winkler` | float | Maximum Jaro-Winkler similarity to the relevant canonical package list, rounded to four decimal places. |

Rows remain present even when source files are missing or parsing fails; unavailable feature values retain their default values, usually `0`.

#### Execution

```bash
python extract_tier1_features.py
```

---

### `extract_tier2_chunks.py`

Scans package source files for calls and patterns associated with potentially sensitive operations and stores short surrounding code contexts.

#### Why it exists

Tier 2 preserves focused evidence for further review without storing or sending every source file as a model input. It is intended to identify code locations that may involve process execution, dynamic evaluation, network communication, environment access, decoding, or similar behavior.

#### Inputs

- `manifest.parquet`
- Package directories referenced by `package_rel_path`
- Python source files for PyPI packages
- JavaScript source files for npm packages

The scanner skips directories named:

```text
 test, tests, docs, doc, fixtures, example, examples, assets, node_modules
```

#### Python detection

Python files are parsed with the AST module. The scanner looks for calls to configured sinks such as:

- `os.system`, `os.popen`, `os.spawn*`, `os.execv`, and `os.environ`
- `subprocess.Popen`, `run`, `call`, `check_output`, and `check_call`
- Base64 decoding functions
- Socket creation and connection functions
- Built-ins such as `eval`, `exec`, and `__import__`

Comments and docstrings are removed before scanning where possible. For each finding, the output includes up to three lines of context before and after the detected call.

#### JavaScript detection

JavaScript files are scanned with regular expressions for patterns including:

- `child_process.exec`, `spawn`, `execSync`, and `fork`
- Imports of `child_process`
- `eval` and `new Function`
- Base64 decoding with `Buffer.from`
- Network connection APIs
- `process.env`
- HTTP and HTTPS requests

JavaScript comments are removed before matching where possible. The scanner records the matching pattern, line number, and surrounding context.

#### Output

The output is written to:

```text
/content/drive/MyDrive/SHIELD_DATA/tier2_chunks.parquet
```

It is a Snappy-compressed Parquet table with one row per manifest package.

#### Tier 2 output data structure

| Column | Type / values | Meaning |
|---|---|---|
| `uid` | string | Package identifier copied from the manifest. |
| `ecosystem` | string: `npm` or `pypi` | Package ecosystem copied from the manifest. |
| `label` | integer: `1` or `0` | Package label copied from the manifest. |
| `sink_count` | integer | Number of detected sink occurrences across eligible source files. |
| `isolated_code_payload` | string | Concatenated code contexts. Individual findings are separated by `\n---\n` and include file name, line number, sink identifier, and nearby sanitized source code. If no findings are detected, the value is `NO_HIGH_RISK_SINKS_DETECTED`. |

A typical non-empty `isolated_code_payload` has this logical form:

```text
[file.py:42 - Sink: subprocess.run]
<nearby sanitized source code>
---
[index.js:18 - Sink: <regular-expression prefix>]
<nearby sanitized source code>
```

The JavaScript `sink` value is the first 25 characters of the regular expression that matched, while Python findings use names such as `subprocess.run` or `eval`.

#### Execution

```bash
python extract_tier2_chunks.py
```

---

## Recommended pipeline order

The scripts are intended to run in this order:

```text
1. Prepare data/seed_lists/*_benign_seeds.json
2. Run extractor.py (or pull_benign_registry.py)
3. Add any malicious package collections under raw_store/malicious if needed
4. Run compile_dataset.py
5. Run extract_tier1_features.py
6. Run extract_tier2_chunks.py
```

The resulting artifacts are:

```text
SHIELD_DATA/
├── raw_store/
│   ├── benign/
│   │   ├── npm/
│   │   ├── pypi/
│   │   ├── npm_failed_ingestion.json       # extractor.py only, when failures occur
│   │   └── pypi_failed_ingestion.json      # extractor.py only, when failures occur
│   └── malicious/
├── shards/
│   ├── shield_shard_001.tar.zst
│   └── ...
├── manifest.parquet
├── tier1_features.parquet
└── tier2_chunks.parquet
```

## Dependencies

The scripts import or rely on the following Python packages and libraries:

- `requests`
- `pandas`
- `pyarrow` for Parquet input/output
- `jellyfish`
- `zstandard`

They also use Python standard-library modules including `ast`, `json`, `tarfile`, `zipfile`, `pathlib`, `hashlib`, `concurrent.futures`, and `re`.

A compatible environment should use a modern Python version with `ast.unparse` support, typically Python 3.9 or newer.

## Limitations and interpretation notes

- The ingestion scripts preserve only selected files, so the raw store is not a complete copy of each package.
- Package archives are downloaded from the current registry metadata at execution time; repeating the pipeline later may produce different versions or results.
- Parsing errors are intentionally tolerated so one malformed package does not stop the complete dataset build. Such rows generally retain default feature values.
- Presence of a sensitive API or install-related file is a review signal, not proof of malicious behavior.
- `compile_dataset.py` labels directories based on their parent collection (`malicious` or `benign`), so the directory layout is part of the labeling contract.
- The `has_install_script` manifest field currently checks for `setup.py` or `package.json`; it does not inspect whether npm lifecycle hooks or custom installation commands are actually defined.
- The shard offset is approximate because it tracks uncompressed file sizes before tar-header overhead and compression.

## Reading the Parquet outputs with pandas

```python
import pandas as pd

manifest = pd.read_parquet("/content/drive/MyDrive/SHIELD_DATA/manifest.parquet")
tier1 = pd.read_parquet("/content/drive/MyDrive/SHIELD_DATA/tier1_features.parquet")
tier2 = pd.read_parquet("/content/drive/MyDrive/SHIELD_DATA/tier2_chunks.parquet")

print(manifest.columns.tolist())
print(tier1.head())
print(tier2[["uid", "sink_count", "isolated_code_payload"]].head())
```
