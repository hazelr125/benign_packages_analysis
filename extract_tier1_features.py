import os
import ast
import json
import re
import tarfile
import io
import pandas as pd
import jellyfish
import zstandard as zstd
from pathlib import Path

# --- Storage Paths ---
DATA_ROOT = Path("/content/drive/MyDrive/SHIELD_DATA/raw_store")
SHARDS_DIR = Path("/content/drive/MyDrive/SHIELD_DATA/shards")
MANIFEST_PATH = Path("/content/drive/MyDrive/SHIELD_DATA/manifest.parquet")
OUTPUT_FEATURES = Path("/content/drive/MyDrive/SHIELD_DATA/tier1_features.parquet")

# --- Top 100 Canonical Targets for Typosquat Distance ---
TOP_NPM = [
    "lodash", "chalk", "react", "express", "commander", "moment", "axios",
    "tslib", "debug", "vue", "request", "async", "prop-types", "fs-extra",
    "body-parser", "bluebird", "uuid", "yargs", "glob", "rxjs", "webpack",
    "mkdirp", "minimist", "underscore", "semver", "core-js", "dotenv",
    "colors", "inherits", "inquirer", "chokidar", "classnames", "superagent",
    "source-map", "babel-core", "postcss", "styled-components", "redis",
    "prettier", "mocha", "eslint", "cheerio", "ws", "path-to-regexp", "rimraf"
]

TOP_PYPI = [
    "urllib3", "six", "botocore", "requests", "certifi", "boto3", "setuptools",
    "python-dateutil", "idna", "charset-normalizer", "s3transfer", "typing-extensions",
    "pip", "wheel", "numpy", "cffi", "pydantic", "pytz", "cryptography", "jinja2",
    "pandas", "attrs", "click", "jmespath", "pyyaml", "packaging", "markupsafe",
    "pluggy", "pytest", "scipy", "virtualenv", "importlib-metadata", "aiohttp",
    "psutil", "tomli", "google-api-python-client", "grpcio", "tqdm", "protobuf"
]

# --- Lexical Distance Calculators ---
def compute_typosquat_metrics(name: str, target_list: list):
    clean_name = name.lower().replace("@", "").split("/")[-1]
    min_lev = 999
    max_jw = 0.0

    for target in target_list:
        lev = jellyfish.levenshtein_distance(clean_name, target)
        jw = jellyfish.jaro_winkler_similarity(clean_name, target)
        if lev < min_lev:
            min_lev = lev
        if jw > max_jw:
            max_jw = jw

    return min_lev, max_jw

# --- Static AST Parser for Python setup.py ---
def parse_setup_py_ast(code_str: str):
    """Statically parses setup.py to detect cmdclass and install requires without execution."""
    features = {
        "author_count": 0,
        "desc_len": 0,
        "has_homepage": 0,
        "dep_count": 0,
        "has_cmdclass": 0
    }

    # Regex fallback for high-risk custom commands if AST fails
    if re.search(r"cmdclass\s*=\s*\{", code_str):
        features["has_cmdclass"] = 1

    try:
        tree = ast.parse(code_str)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if func_name == "setup":
                    for keyword in node.keywords:
                        k = keyword.arg
                        # ETM: Description length
                        if k == "description" and isinstance(keyword.value, ast.Constant):
                            features["desc_len"] = len(str(keyword.value.value))
                        # ETM: Homepage / Repositories
                        elif k in ["url", "project_urls"]:
                            features["has_homepage"] = 1
                        # ETM: Author count
                        elif k in ["author", "maintainer"]:
                            features["author_count"] += 1
                        # DTM: Dependencies
                        elif k == "install_requires" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                            features["dep_count"] = len(keyword.value.elts)
                        # Lifecycle Hooks: cmdclass override
                        elif k == "cmdclass":
                            features["has_cmdclass"] = 1
    except Exception:
        # Fallback to regex heuristic on syntax error
        pass

    return features

# --- Parser for npm package.json ---
def parse_package_json(content_str: str):
    features = {
        "desc_len": 0,
        "has_readme": 0,
        "author_count": 0,
        "has_homepage": 0,
        "dep_count": 0,
        "dev_dep_count": 0,
        "has_preinstall": 0,
        "has_postinstall": 0
    }
    try:
        data = json.loads(content_str)
        desc = data.get("description", "")
        features["desc_len"] = len(desc) if isinstance(desc, str) else 0
        features["has_readme"] = 1 if data.get("readme") else 0

        # Authors & maintainers count
        authors = data.get("author") or data.get("contributors") or data.get("maintainers") or []
        if isinstance(authors, list):
            features["author_count"] = len(authors)
        elif isinstance(authors, (dict, str)):
            features["author_count"] = 1

        features["has_homepage"] = 1 if data.get("homepage") or data.get("repository") else 0
        features["dep_count"] = len(data.get("dependencies", {}))
        features["dev_dep_count"] = len(data.get("devDependencies", {}))

        # Lifecycle Hooks Check
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            if "preinstall" in scripts:
                features["has_preinstall"] = 1
            if "postinstall" in scripts or "install" in scripts:
                features["has_postinstall"] = 1
    except Exception:
        pass

    return features

# --- Main Ingestion Loop ---
def extract_metadata_features():
    df_manifest = pd.read_parquet(MANIFEST_PATH)
    print(f"[*] Extracting Tier-1 features across {len(df_manifest)} indexed packages...")

    feature_rows = []

    for _, row in df_manifest.iterrows():
        uid = row["uid"]
        ecosystem = row["ecosystem"]
        label = row["label"]
        rel_path = row["package_rel_path"]
        pkg_full_path = DATA_ROOT / rel_path

        # Derive Package Name for Typo Distance
        pkg_name = Path(rel_path).parts[1] if len(Path(rel_path).parts) > 1 else "unknown"
        target_reference = TOP_NPM if ecosystem == "npm" else TOP_PYPI
        min_lev, max_jw = compute_typosquat_metrics(pkg_name, target_reference)

        extracted = {
            "uid": uid,
            "ecosystem": 1 if ecosystem == "npm" else 0,
            "label": label,
            "desc_len": 0,
            "has_readme": 0,
            "author_count": 0,
            "has_homepage": 0,
            "dep_count": 0,
            "dev_dep_count": 0,
            "has_preinstall": 0,
            "has_postinstall": 0,
            "has_cmdclass": 0,
            "min_levenshtein": min_lev,
            "max_jaro_winkler": round(max_jw, 4)
        }

        # 1. Parse NPM Ecosystem
        if ecosystem == "npm":
            target_file = pkg_full_path / "package.json"
            if target_file.exists():
                try:
                    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                        extracted.update(parse_package_json(f.read()))
                except Exception:
                    pass

        # 2. Parse PyPI Ecosystem
        elif ecosystem == "pypi":
            setup_file = pkg_full_path / "setup.py"
            pkg_info_file = pkg_full_path / "PKG-INFO"

            # Parse AST from setup.py
            if setup_file.exists():
                try:
                    with open(setup_file, "r", encoding="utf-8", errors="ignore") as f:
                        ast_data = parse_setup_py_ast(f.read())
                        extracted.update(ast_data)
                except Exception:
                    pass

            # Augment ETM fields from PKG-INFO fallback if description is missing
            if pkg_info_file.exists() and extracted["desc_len"] == 0:
                try:
                    with open(pkg_info_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("Summary:"):
                                extracted["desc_len"] = len(line.replace("Summary:", "").strip())
                            elif line.startswith("Home-page:") or line.startswith("Project-URL:"):
                                extracted["has_homepage"] = 1
                            elif line.startswith("Author:") and extracted["author_count"] == 0:
                                extracted["author_count"] = 1
                except Exception:
                    pass

        feature_rows.append(extracted)

    df_features = pd.DataFrame(feature_rows)
    df_features.to_parquet(OUTPUT_FEATURES, engine="pyarrow", compression="snappy")
    print(f"[✓] Tier-1 metadata features extracted: {len(df_features)} records saved to {OUTPUT_FEATURES}")
    print(df_features.describe())

if __name__ == "__main__":

    extract_metadata_features()
