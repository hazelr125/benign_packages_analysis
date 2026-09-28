import os
import ast
import re
import json
import pandas as pd
from pathlib import Path

DATA_ROOT = Path("/content/drive/MyDrive/SHIELD_DATA/raw_store")
MANIFEST_PATH = Path("/content/drive/MyDrive/SHIELD_DATA/manifest.parquet")
OUTPUT_CHUNKS_PATH = Path("/content/drive/MyDrive/SHIELD_DATA/tier2_chunks.parquet")

# Excluded directory trees
IGNORED_DIRS = {"test", "tests", "docs", "doc", "fixtures", "example", "examples", "assets", "node_modules"}

# Sinks to monitor for Python
PY_SINKS = {
    "os": {"system", "popen", "spawn", "execv", "environ"},
    "subprocess": {"Popen", "run", "call", "check_output", "check_call"},
    "base64": {"b64decode", "standard_b64decode", "urlsafe_b64decode"},
    "socket": {"socket", "connect"},
    "builtins": {"eval", "exec", "__import__"}
}

# Sinks to monitor for JavaScript (Regex-based lexical extraction)
JS_SINK_PATTERNS = [
    re.compile(r"child_process\s*\.\s*(exec|spawn|execSync|fork)\s*\(", re.IGNORECASE),
    re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
    re.compile(r"Buffer\s*\.\s*from\s*\([^)]*['\"]base64['\"]\)", re.IGNORECASE),
    re.compile(r"net\s*\.\s*(connect|createConnection)\s*\(", re.IGNORECASE),
    re.compile(r"process\s*\.\s*env", re.IGNORECASE),
    re.compile(r"(http|https)\s*\.\s*(get|request)\s*\(", re.IGNORECASE)
]

def sanitize_python_code(code_str: str) -> str:
    """Removes comments and docstrings from Python code."""
    try:
        parsed = ast.parse(code_str)
        for node in ast.walk(parsed):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
                if (node.body and isinstance(node.body[0], ast.Expr) and
                        isinstance(node.body[0].value, ast.Constant) and
                        isinstance(node.body[0].value.value, str)):
                    node.body.pop(0)
        return ast.unparse(parsed)
    except Exception:
        # Fallback to regex comment stripping
        return re.sub(r"#.*", "", code_str)

def sanitize_js_code(code_str: str) -> str:
    """Removes single-line and multi-line comments from JavaScript."""
    pattern = r"(\".*?\"|\'.*?\')|(/\*.*?\*/|//[^\r\n]*$)"
    regex = re.compile(pattern, re.MULTILINE | re.DOTALL)
    def replacer(match):
        return match.group(1) if match.group(1) else ""
    clean = regex.sub(replacer, code_str)
    return "\n".join([line.strip() for line in clean.splitlines() if line.strip()])

def extract_python_sinks(file_path: Path, max_context_lines=3) -> list:
    """Uses AST to locate call nodes matching sensitive APIs and extracts surrounding code lines."""
    findings = []
    try:
        raw_code = file_path.read_text(encoding="utf-8", errors="ignore")
        clean_code = sanitize_python_code(raw_code)
        lines = clean_code.splitlines()
        tree = ast.parse(clean_code)

        for node in ast.walk(tree):
            sink_detected = None
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    val_id = getattr(node.func.value, "id", None)
                    attr_name = node.func.attr
                    if val_id in PY_SINKS and attr_name in PY_SINKS[val_id]:
                        sink_detected = f"{val_id}.{attr_name}"
                elif isinstance(node.func, ast.Name):
                    if node.func.id in PY_SINKS["builtins"]:
                        sink_detected = node.func.id

            if sink_detected and hasattr(node, "lineno"):
                line_idx = node.lineno - 1
                start = max(0, line_idx - max_context_lines)
                end = min(len(lines), line_idx + max_context_lines + 1)
                context_slice = "\n".join(lines[start:end])
                findings.append({
                    "file": file_path.name,
                    "sink": sink_detected,
                    "line": node.lineno,
                    "context": context_slice
                })
    except Exception:
        pass
    return findings

def extract_js_sinks(file_path: Path, max_context_lines=3) -> list:
    """Scans JavaScript source files for pattern-matched sink signatures."""
    findings = []
    try:
        raw_code = file_path.read_text(encoding="utf-8", errors="ignore")
        clean_code = sanitize_js_code(raw_code)
        lines = clean_code.splitlines()

        for idx, line in enumerate(lines):
            for pat in JS_SINK_PATTERNS:
                if pat.search(line):
                    start = max(0, idx - max_context_lines)
                    end = min(len(lines), idx + max_context_lines + 1)
                    findings.append({
                        "file": file_path.name,
                        "sink": pat.pattern[:25],
                        "line": idx + 1,
                        "context": "\n".join(lines[start:end])
                    })
                    break
    except Exception:
        pass
    return findings

def process_package_chunks(pkg_dir: Path, ecosystem: str) -> list:
    """Scans eligible package files, excluding documentation and test directories."""
    all_chunks = []
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIRS]
        for f in files:
            file_path = Path(root) / f
            if ecosystem == "pypi" and f.endswith(".py"):
                chunks = extract_python_sinks(file_path)
                all_chunks.extend(chunks)
            elif ecosystem == "npm" and f.endswith(".js"):
                chunks = extract_js_sinks(file_path)
                all_chunks.extend(chunks)
    return all_chunks

def build_tier2_dataset():
    df_manifest = pd.read_parquet(MANIFEST_PATH)
    print(f"[*] Building Tier-2 AST Context Payloads across {len(df_manifest)} packages...")

    records = []
    for _, row in df_manifest.iterrows():
        uid = row["uid"]
        ecosystem = row["ecosystem"]
        label = row["label"]
        rel_path = row["package_rel_path"]
        pkg_full_path = DATA_ROOT / rel_path

        chunks = []
        if pkg_full_path.exists():
            chunks = process_package_chunks(pkg_full_path, ecosystem)

        # Build collapsed LLM prompt content
        if chunks:
            chunk_text = "\n---\n".join([f"[{c['file']}:{c['line']} - Sink: {c['sink']}]\n{c['context']}" for c in chunks])
        else:
            chunk_text = "NO_HIGH_RISK_SINKS_DETECTED"

        records.append({
            "uid": uid,
            "ecosystem": ecosystem,
            "label": label,
            "sink_count": len(chunks),
            "isolated_code_payload": chunk_text
        })

    out_df = pd.DataFrame(records)
    out_df.to_parquet(OUTPUT_CHUNKS_PATH, engine="pyarrow", compression="snappy")
    print(f"[✓] Tier-2 chunks compiled: {len(out_df)} records saved to {OUTPUT_CHUNKS_PATH}")
    print(out_df["sink_count"].describe())

if __name__ == "__main__":
    build_tier2_dataset()
