import os
import sys
import json
import hashlib
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    import magic
except ImportError:
    print("Error: 'python-magic' is not installed. Run: pip install python-magic")
    sys.exit(1)

# ─────────────────────────────────────────────
#  Logging setup
# ─────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_FILE   = SCRIPT_DIR / "file_analysis.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
DANGEROUS_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-sh",
    "application/x-bat",
    "text/x-shellscript",
}

SIZE_UNITS = ["B", "KB", "MB", "GB", "TB"]

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def format_size(num_bytes: int) -> str:
    """Convert raw bytes into a human-readable size string."""
    value = float(num_bytes)
    for unit in SIZE_UNITS:
        if value < 1024:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} PB"


def compute_hashes(file_path: Path) -> dict[str, str]:
    """Return MD5 and SHA-256 hashes of a file."""
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def is_dangerous(mime_type: str) -> bool:
    return mime_type in DANGEROUS_MIME_TYPES


# ─────────────────────────────────────────────
#  Core analysis
# ─────────────────────────────────────────────
def analyze_file(file_path: str, include_hashes: bool = False) -> dict:
    """
    Full analysis of a single file.

    Returns a dict with keys:
        path, name, extension, size, size_bytes,
        mime_type, readable_type, dangerous,
        modified, created,
        hashes (optional),
        error (on failure)
    """
    path = Path(file_path.strip('"').strip("'"))  # handle drag-and-drop quoted paths

    # ── Existence check ──────────────────────
    if not path.exists():
        msg = "File does not exist."
        logger.warning(f"{path} | {msg}")
        return {"error": msg, "path": str(path)}

    if not path.is_file():
        msg = "Path is a directory, not a file."
        logger.warning(f"{path} | {msg}")
        return {"error": msg, "path": str(path)}

    if not os.access(path, os.R_OK):
        msg = "Permission denied — cannot read file."
        logger.warning(f"{path} | {msg}")
        return {"error": msg, "path": str(path)}

    try:
        stat = path.stat()

        mime_type    = magic.Magic(mime=True).from_file(str(path))
        readable     = magic.Magic(mime=False).from_file(str(path))
        dangerous    = is_dangerous(mime_type)

        result: dict = {
            "path":         str(path.resolve()),
            "name":         path.name,
            "extension":    path.suffix.lower() or "(none)",
            "size":         format_size(stat.st_size),
            "size_bytes":   stat.st_size,
            "mime_type":    mime_type,
            "readable_type": readable,
            "dangerous":    dangerous,
            "modified":     datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "created":      datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        }

        if include_hashes:
            result["hashes"] = compute_hashes(path)

        logger.info(f"{path} | MIME={mime_type} | size={stat.st_size}B | dangerous={dangerous}")
        return result

    except Exception as e:
        msg = f"Analysis failed: {e}"
        logger.error(f"{path} | {msg}")
        return {"error": msg, "path": str(path)}


def analyze_batch(paths: list[str], include_hashes: bool = False) -> list[dict]:
    """Analyze multiple files and return a list of results."""
    return [analyze_file(p, include_hashes) for p in paths]


# ─────────────────────────────────────────────
#  Display
# ─────────────────────────────────────────────
def print_result(result: dict, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print(f"\n  ✗  {result['error']}")
        return

    danger_tag = "  ⚠  POTENTIALLY DANGEROUS EXECUTABLE" if result["dangerous"] else ""
    print(f"""
┌─ File Analysis ────────────────────────────────────────┐
  Name       : {result['name']}
  Path       : {result['path']}
  Extension  : {result['extension']}
  Size       : {result['size']} ({result['size_bytes']:,} bytes)
  MIME Type  : {result['mime_type']}
  Type       : {result['readable_type']}
  Modified   : {result['modified']}
  Created    : {result['created']}{danger_tag}""")

    if "hashes" in result:
        print(f"  MD5        : {result['hashes']['md5']}")
        print(f"  SHA-256    : {result['hashes']['sha256']}")

    print("└────────────────────────────────────────────────────────┘")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="file_analysis",
        description="Analyze files by magic number — MIME type, size, hashes, and more.",
    )
    p.add_argument("files", nargs="*", help="Files to analyze (skips interactive mode)")
    p.add_argument("--hashes", action="store_true", help="Include MD5 and SHA-256 hashes")
    p.add_argument("--json",   action="store_true", help="Output results as JSON")
    p.add_argument("--batch",  metavar="LIST_FILE",
                   help="Path to a text file containing one file path per line")
    return p


def interactive_mode(include_hashes: bool, as_json: bool) -> None:
    print("File Analysis Tool  |  type 'exit' to quit, 'help' for options")
    print("-" * 60)
    while True:
        try:
            raw = input("\nFile path: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not raw:
            continue
        if raw.lower() in ("exit", "quit", "q"):
            print("Goodbye!")
            break
        if raw.lower() == "help":
            print("  • Enter a file path to analyze it")
            print("  • Drag and drop a file into the terminal")
            print(f"  • Logs saved to: {LOG_FILE}")
            continue

        result = analyze_file(raw, include_hashes)
        print_result(result, as_json)


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    targets: list[str] = list(args.files)

    # Batch file mode
    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.is_file():
            print(f"Batch file not found: {args.batch}")
            sys.exit(1)
        targets += [line.strip() for line in batch_path.read_text().splitlines() if line.strip()]

    if targets:
        results = analyze_batch(targets, include_hashes=args.hashes)
        for r in results:
            print_result(r, as_json=args.json)
    else:
        interactive_mode(include_hashes=args.hashes, as_json=args.json)


if __name__ == "__main__":
    main()