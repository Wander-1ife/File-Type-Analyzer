# File Type Analyzer

## Overview
File Type Analyzer is a Python-based tool that detects the MIME type and human-readable file type of a given file using its magic number. It logs the analysis results for future reference.

## Features
- Identifies file types using `python-magic`
- Provides both MIME type and human-readable file type
- Logs analysis results to `file_analysis.log`
- Handles errors and missing dependencies gracefully
- Interactive command-line interface

## Requirements
Ensure you have the necessary dependencies installed before running the script:

```bash
pip install python-magic
```

For Linux users, you may also need to install `libmagic`:

```bash
sudo apt install libmagic1
```

## Usage
1. Run the script:
   ```bash
   python file_analyzer.py
   ```
2. Enter the full path of the file you want to analyze.
3. The tool will display the detected file type information.
4. To exit, type `exit` when prompted for a file path.

## Log File
All results are logged in `file_analysis.log`, located in the same directory as the script. Each entry includes the file path, MIME type, and human-readable type.

## Notes
- If `python-magic` is missing, the script will prompt an error message.
- The tool does not modify files; it only reads their metadata.

## Disclaimer
This tool is intended for educational and forensic purposes. The developer is not responsible for any misuse.

