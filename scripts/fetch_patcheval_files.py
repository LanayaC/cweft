"""
Freeze the PatchEval vulnerable source files into the repo.

Writes, for every manifest entry whose primary_cwe_covered is true (109):
    data/patcheval/files/<CVE-ID>/<vulnerable_file_path>   the file, byte for byte
    data/patcheval/manifest.json                            one object per entry

so generate.py can build prompts with no Docker. Evaluation still needs each
entry's image; the recorded sha256 lets it confirm the image holds the same
file the model was shown.

Source of truth is the dataset's own gate run (cweft_dataset/analysis):
meta_git_cache.json records, per CVE, the vulnerable commit and the git blob
id of the vulnerable file, i.e. the exact bytes the manifest's token_count was
measured on. Each file is read from the local bare-repo cache under
analysis/out/git/ (raw.githubusercontent.com only if the blob is missing) and
accepted only if its git blob hash equals that id. Files already extracted
from the Docker images (analysis/out/images/) are compared as a cross-check.

    python scripts/fetch_patcheval_files.py
    python scripts/fetch_patcheval_files.py --dataset-root D:/cweft_dataset
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = PROJECT_ROOT / "data" / "patcheval"
FILES_DIR = OUT_DIR / "files"

# The prompt language follows the file, not PatchEval's label: its one .ts
# entry is labelled JavaScript, but calling it that would invite the model
# to strip the type annotations.
PROMPT_LANGUAGE_BY_EXT = {".go": "Go", ".js": "JavaScript", ".ts": "TypeScript", ".py": "Python"}


def git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def owner_repo(url: str):
    m = re.match(r"https://github\.com/([^/]+)/([^/#?]+)", url.rstrip("/"))
    if not m:
        raise ValueError(f"not a GitHub repo URL: {url}")
    return m.group(1), m.group(2).removesuffix(".git")


def read_blob(git_dir: Path, oid: str, raw_url: str):
    """Return (bytes, source) for a blob, from the local cache or GitHub."""
    if git_dir.is_dir():
        proc = subprocess.run(["git", "-C", str(git_dir), "cat-file", "blob", oid],
                              capture_output=True, timeout=600)
        if proc.returncode == 0:
            return proc.stdout, "git-cache"
    with urllib.request.urlopen(raw_url, timeout=60) as r:
        return r.read(), "github-raw"


def image_copy(images_dir: Path, cve: str, rel_path: str):
    """The same file as extracted from the Docker image, if we have it."""
    root = images_dir / cve / "files"
    if not root.is_dir():
        return None
    hits = [p for p in root.rglob(PurePosixPath(rel_path).name)
            if p.as_posix().endswith("/" + rel_path)]
    return hits[0].read_bytes() if len(hits) == 1 else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dataset-root", type=Path, default=PROJECT_ROOT.parent / "cweft_dataset")
    args = ap.parse_args()

    root = args.dataset_root
    manifest = json.loads((root / "data" / "patcheval_manifest.json").read_text(encoding="utf-8"))
    git_cache = json.loads((root / "analysis" / "out" / "meta_git_cache.json").read_text(encoding="utf-8"))
    hf = {e["cve_id"]: e for e in json.loads(
        (root / "hf_patcheval" / "patcheval_verified.json").read_text(encoding="utf-8"))}
    git_root = root / "analysis" / "out" / "git"
    images_dir = root / "analysis" / "out" / "images"

    entries = [e for e in manifest if e["primary_cwe_covered"] is True]
    out, problems, sources, cross_checked = [], [], {}, 0

    for e in entries:
        cve, rel = e["cve_id"], e["vulnerable_file_path"]
        rel_p = PurePosixPath(rel)
        if rel_p.is_absolute() or ".." in rel_p.parts:
            problems.append(f"{cve}: unsafe path {rel!r}")
            continue

        g = git_cache.get(cve) or {}
        blob = (g.get("blobs") or {}).get(rel) or {}
        oid, vul_commit = blob.get("oid"), g.get("vul_commit")
        if not oid or not vul_commit:
            problems.append(f"{cve}: no blob id / vulnerable commit in meta_git_cache.json")
            continue
        if blob.get("tokens") != e["token_count"]:
            problems.append(f"{cve}: cache token count {blob.get('tokens')} != manifest {e['token_count']}")
            continue

        repo = hf[cve]["repo"]
        o, r = owner_repo(repo)
        git_dir = git_root / f"{o}__{r}.git".lower()
        raw_url = f"https://raw.githubusercontent.com/{o}/{r}/{vul_commit}/{rel}"
        try:
            data, source = read_blob(git_dir, oid, raw_url)
        except Exception as ex:
            problems.append(f"{cve}: could not read blob {oid}: {type(ex).__name__}: {ex}")
            continue
        if git_blob_id(data) != oid:
            problems.append(f"{cve}: fetched bytes hash to {git_blob_id(data)}, expected blob {oid}")
            continue
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as ex:
            problems.append(f"{cve}: not valid UTF-8 ({ex})")
            continue

        img = image_copy(images_dir, cve, rel)
        if img is not None:
            cross_checked += 1
            if img != data:
                problems.append(f"{cve}: file in the Docker image differs from the vulnerable-commit blob")
                continue

        ext = rel_p.suffix
        if ext not in PROMPT_LANGUAGE_BY_EXT:
            problems.append(f"{cve}: no prompt language for extension {ext!r}")
            continue

        dest = FILES_DIR / cve / rel_p
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        sources[source] = sources.get(source, 0) + 1

        out.append({
            "cve_id":               cve,
            "language":             e["language"],
            "prompt_language":      PROMPT_LANGUAGE_BY_EXT[ext],
            "primary_cwe":          e["primary_cwe"],
            "primary_cwe_name":     e["primary_cwe_name"],
            "cwe_list":             e["cwe_list"],
            "vulnerable_file_path": rel,
            "token_count":          e["token_count"],
            "bytes":                len(data),
            "sha256":               hashlib.sha256(data).hexdigest(),
            "git_blob_id":          oid,
            "repo":                 repo,
            "vul_commit":           vul_commit,
            "docker_image":         e["docker_image"],
        })

    if problems:
        print(f"FAILED: {len(problems)} problem(s); manifest not written.")
        for p in problems:
            print("  " + p)
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "manifest.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(out)} files under {FILES_DIR.relative_to(PROJECT_ROOT)} "
          f"(sources: {sources}); {cross_checked} matched their Docker-image copy.")
    print(f"Wrote {(OUT_DIR / 'manifest.json').relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
