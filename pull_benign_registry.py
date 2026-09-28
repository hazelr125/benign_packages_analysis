import os
import io
import json
import time
import tarfile
import zipfile
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_STORAGE = Path("/content/drive/MyDrive/SHIELD_DATA/raw_store/benign")
NPM_STORAGE = BASE_STORAGE / "npm"
PYPI_STORAGE = BASE_STORAGE / "pypi"

NPM_STORAGE.mkdir(parents=True, exist_ok=True)
PYPI_STORAGE.mkdir(parents=True, exist_ok=True)

# Files critical for Tier-1 Metadata & Tier-2 AST Chunking
TARGET_FILES = {
    "package.json", "setup.py", "setup.cfg", "pyproject.toml",
    "preinstall.js", "postinstall.js", "index.js", "__init__.py"
}

def extract_selective(archive_bytes: bytes, target_dir: Path, is_zip=False):
    """Extracts only critical entry points and scripts to conserve space."""
    target_dir.mkdir(parents=True, exist_ok=True)
    if is_zip:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
            for member in z.namelist():
                base_name = os.path.basename(member)
                if base_name in TARGET_FILES:
                    out_path = target_dir / base_name
                    with open(out_path, "wb") as f:
                        f.write(z.read(member))
    else:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tar:
            for member in tar.getmembers():
                base_name = os.path.basename(member.name)
                if base_name in TARGET_FILES and member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        out_path = target_dir / base_name
                        with open(out_path, "wb") as out:
                            out.write(f.read())

def fetch_npm_package(session: requests.Session, pkg_name: str):
    """Fetches npm latest package metadata and unpacks build hooks & entrypoint."""
    meta_url = f"https://registry.npmjs.org/{pkg_name}"
    try:
        r = session.get(meta_url, timeout=12)
        if r.status_code != 200:
            return False, pkg_name, f"HTTP {r.status_code}"

        doc = r.json()
        latest_ver = doc.get("dist-tags", {}).get("latest")
        if not latest_ver or latest_ver not in doc.get("versions", {}):
            return False, pkg_name, "No latest release"

        dist = doc["versions"][latest_ver].get("dist", {})
        tarball_url = dist.get("tarball")
        if not tarball_url:
            return False, pkg_name, "No tarball URL"

        tar_resp = session.get(tarball_url, timeout=20)
        if tar_resp.status_code == 200:
            target_path = NPM_STORAGE / pkg_name / latest_ver
            extract_selective(tar_resp.content, target_path, is_zip=False)
            return True, pkg_name, "Success"
        return False, pkg_name, f"Download failed: {tar_resp.status_code}"
    except Exception as e:
        return False, pkg_name, str(e)

def fetch_pypi_package(session: requests.Session, pkg_name: str):
    """Fetches PyPI sdist package to guarantee preservation of setup.py."""
    meta_url = f"https://pypi.org/pypi/{pkg_name}/json"
    try:
        r = session.get(meta_url, timeout=12)
        if r.status_code != 200:
            return False, pkg_name, f"HTTP {r.status_code}"

        doc = r.json()
        version = doc.get("info", {}).get("version")
        releases = doc.get("releases", {}).get(version, [])

        # Prioritize source distributions (.tar.gz / .zip) over .whl
        sdist = next((rel for rel in releases if rel.get("packagetype") == "sdist"), None)
        is_zip = False
        if not sdist and releases:
            sdist = releases[0]
            is_zip = sdist["filename"].endswith((".zip", ".whl"))
        if not sdist:
            return False, pkg_name, "No release files found"

        file_url = sdist.get("url")
        file_resp = session.get(file_url, timeout=20)
        if file_resp.status_code == 200:
            target_path = PYPI_STORAGE / pkg_name / version
            extract_selective(file_resp.content, target_path, is_zip=is_zip)
            return True, pkg_name, "Success"
        return False, pkg_name, f"Download failed: {file_resp.status_code}"
    except Exception as e:
        return False, pkg_name, str(e)

def execute_ingestion_worker(ecosystem: str, workers=16):
    seed_file = Path(f"data/seed_lists/{ecosystem}_benign_seeds.json")
    if not seed_file.exists():
        raise FileNotFoundError(f"Missing {seed_file}. Run generate_pull_lists.py first.")

    with open(seed_file, "r") as f:
        pkg_list = json.load(f)

    print(f"[*] Starting ingestion for {len(pkg_list)} {ecosystem} packages with {workers} threads...")

    session = requests.Session()
    # Adapter connection pooling prevents port exhaustion
    adapter = requests.adapters.HTTPAdapter(pool_connections=workers, pool_maxsize=workers * 2, max_retries=2)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    fetch_fn = fetch_npm_package if ecosystem == "npm" else fetch_pypi_package

    success, fail = 0, 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(fetch_fn, session, name): name for name in pkg_list}
        for future in as_completed(futures):
            ok, name, status = future.result()
            if ok:
                success += 1
            else:
                fail += 1
            if (success + fail) % 250 == 0:
                elapsed = time.time() - start_time
                print(f"[{ecosystem.upper()}] Processed: {success + fail}/{len(pkg_list)} | Success: {success} | Failed: {fail} | Speed: {(success + fail) / elapsed:.1f} pkg/s")

    print(f"[✓] {ecosystem.upper()} complete. Successfully preserved: {success}, Skipped/Failed: {fail}")

if __name__ == "__main__":
    execute_ingestion_worker("npm", workers=12)
    execute_ingestion_worker("pypi", workers=12)
