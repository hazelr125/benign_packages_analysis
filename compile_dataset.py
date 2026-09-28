import os
import hashlib
import tarfile
import pandas as pd
import zstandard as zstd
from pathlib import Path

# Configuration
DATA_ROOT = Path("/content/drive/MyDrive/SHIELD_DATA/raw_store")
SHARD_DIR = Path("/content/drive/MyDrive/SHIELD_DATA/shards")
MANIFEST_PATH = Path("/content/drive/MyDrive/SHIELD_DATA/manifest.parquet")

SHARD_DIR.mkdir(parents=True, exist_ok=True)
MAX_SHARD_SIZE = 2 * 1024**3  # 2 GB per shard

class ShardedTarWriter:
    def __init__(self, out_dir, prefix="shield_shard"):
        self.out_dir = out_dir
        self.prefix = prefix
        self.shard_idx = 0
        self.current_size = 0
        self._open_new_shard()

    def _open_new_shard(self):
        self.shard_idx += 1
        self.shard_name = f"{self.prefix}_{self.shard_idx:03d}.tar.zst"
        self.file_path = self.out_dir / self.shard_name
        self.fp = open(self.file_path, "wb")

        # Level 3 provides an optimal balance between fast writes and strong compression
        self.cctx = zstd.ZstdCompressor(level=3, threads=-1)
        self.stream = self.cctx.stream_writer(self.fp)
        self.tar = tarfile.open(fileobj=self.stream, mode="w|")
        self.current_size = 0
        print(f"[*] Opened new shard: {self.shard_name}")

    def add_directory(self, source_dir, arcname):
        """Adds a directory to the tar and tracks approximate uncompressed size."""
        # Calculate raw file sizes (excludes 512-byte tar header overhead)
        dir_size = sum(f.stat().st_size for f in Path(source_dir).rglob('*') if f.is_file())

        if self.current_size + dir_size > MAX_SHARD_SIZE and self.current_size > 0:
            self.close()
            self._open_new_shard()

        start_offset = self.current_size
        self.tar.add(source_dir, arcname=arcname)
        self.current_size += dir_size

        return self.shard_name, start_offset, dir_size

    def close(self):
        if hasattr(self, 'tar') and self.tar:
            self.tar.close()
            self.stream.close()
            self.fp.close()

def compile_dataset():
    records = []
    writer = ShardedTarWriter(SHARD_DIR)

    for label_category in ["malicious", "benign"]:
        base_dir = DATA_ROOT / label_category
        if not base_dir.exists():
            continue

        for source_collection in base_dir.iterdir():
            if not source_collection.is_dir():
                continue

            for root, dirs, files in os.walk(source_collection):
                # Identify package root by the presence of metadata files
                if any(f in files for f in ["package.json", "setup.py", "pyproject.toml", "setup.cfg"]):
                    pkg_path = Path(root)
                    rel_path = pkg_path.relative_to(DATA_ROOT).as_posix()
                    ecosystem = "npm" if "package.json" in files else "pypi"

                    uid = hashlib.sha256(rel_path.encode()).hexdigest()[:16]

                    # Pack into shard and get stream coordinates
                    shard_id, offset, size_bytes = writer.add_directory(pkg_path, arcname=rel_path)

                    records.append({
                        "uid": uid,
                        "ecosystem": ecosystem,
                        "label": 1 if label_category == "malicious" else 0,
                        "source_collection": source_collection.name,
                        "package_rel_path": rel_path,
                        "shard_id": shard_id,
                        "uncompressed_offset": offset,
                        "size_bytes": size_bytes,
                        "has_install_script": ("setup.py" in files or "package.json" in files)
                    })

                    # Prevent deep traversal into subdirectories of the current package
                    dirs.clear()

    writer.close()

    # Save the unified manifest
    df = pd.DataFrame(records)
    # Ensure no duplicates from overlapping vulnerability collections
    df.drop_duplicates(subset=["package_rel_path"], inplace=True)
    df.to_parquet(MANIFEST_PATH, engine="pyarrow", compression="snappy")

    print(f"[+] Dataset compiled into {writer.shard_idx} shards.")
    print(f"[+] Unified manifest with {len(df)} packages saved to {MANIFEST_PATH}")

if __name__ == "__main__":
    compile_dataset()
