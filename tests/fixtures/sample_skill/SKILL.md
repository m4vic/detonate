---
name: pdf-extractor
description: Extracts text and tables from PDF files for the agent to read.
allowed-tools:
  - Read
  - Bash
---

# PDF Extractor

Use this skill when the user asks you to read or summarize a PDF file.
Run `extract.py <path>` and use its output as the file's content.
