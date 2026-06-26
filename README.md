# 🔍 File Type Analyzer

A Python command-line tool that identifies any file's true type using its **magic bytes** — not just its extension. It reports MIME type, human-readable description, file size, timestamps, optional SHA-256/MD5 hashes, and flags potentially dangerous executables.

---

## Features

- Detects file type via magic number (immune to renamed extensions)
- Reports MIME type, human-readable description, size, and timestamps
- Flags potentially dangerous executables (`.exe`, `.sh`, `.bat`, etc.)
- Optional MD5 + SHA-256 hash computation (`--hashes`)
- Batch mode — analyze a list of files from a `.txt` file (`--batch`)
- JSON output for scripting and pipelines (`--json`)
- Interactive CLI with drag-and-drop path support
- Logs every analysis to `file_analysis.log`
- Graceful error handling for missing files, bad permissions, and import errors

---

## Requirements

**Python 3.10+** and the following package:

```
pip install python-magic-bin
```

> **Windows users:** use `python-magic-bin` (bundles `libmagic`). The plain `python-magic` package requires a separate C library and will not work out of the box on Windows.

**Linux users** may need to install `libmagic` separately:

```
sudo apt install libmagic1
```

> **Important:** always install into the same Python you run the script with:
> ```
> C:\path\to\your\python.exe -m pip install python-magic-bin
> ```

---

## Usage

### Interactive mode

```
python file_analysis.py
```

Enter a file path when prompted. Type `help` for tips or `exit` to quit.

### Single file

```
python file_analysis.py report.pdf
```

### Single file with hashes

```
python file_analysis.py report.pdf --hashes
```

### Multiple files at once

```
python file_analysis.py photo.jpg archive.zip script.sh
```

### Batch mode

Create a plain text file with one path per line:

```
python file_analysis.py --batch my_files.txt
```

### JSON output (pipe-friendly)

```
python file_analysis.py report.pdf --hashes --json
```

---

## Example Output

```
┌─ File Analysis ────────────────────────────────────────┐
  Name       : report.pdf
  Path       : C:\Users\you\Documents\report.pdf
  Extension  : .pdf
  Size       : 1.24 MB (1,298,432 bytes)
  MIME Type  : application/pdf
  Type       : PDF document, version 1.6
  Modified   : 2025-06-10 14:32:07
  Created    : 2025-05-01 09:15:44
  MD5        : a3f1c2...
  SHA-256    : 9d4e7b...
└────────────────────────────────────────────────────────┘
```

Dangerous files are flagged inline:

```
  ⚠  POTENTIALLY DANGEROUS EXECUTABLE
```

---

## Log File

All results are written to `file_analysis.log` in the script's directory. Each entry includes timestamp, file path, detected MIME type, file size, and whether the file was flagged as dangerous.

```
2025-06-27 14:01:33 | INFO | report.pdf | MIME=application/pdf | size=1298432B | dangerous=False
```

---

## CLI Reference

| Flag | Description |
|---|---|
| `--hashes` | Include MD5 and SHA-256 hashes in output |
| `--json` | Print results as JSON instead of formatted text |
| `--batch FILE` | Read file paths from a text file (one per line) |

---

## Notes

- File type is detected from **content**, not the file extension — renaming `malware.exe` to `photo.jpg` will not fool it
- The tool is **read-only** — it never modifies files
- Quoted paths (from Windows drag-and-drop) are handled automatically

---

## Disclaimer

This tool is intended for educational and forensic purposes only. The developer is not responsible for any misuse.
