# shellcode-carver

Shellcode Carver is a portable Python tool that extracts and decodes shellcode from source files, scripts, and logs. It detects byte arrays and Base64 blobs across languages like C, C++, C#, PowerShell, and JavaScript. It works out of the box on REMnux, Linux, or Windows.

I struggled to find a reliable shellcode carver, so I created one. This aims to speed up malware analysis by pulling out likely shellcode from messy or obfuscated files. It looks for byte arrays and Base64 blobs that malware commonly uses. The output is a deduplicated list of regions printed as lowercase hex. Use it directly or feed it into whatever tools you like.

---

## Features

* Parses byte arrays in hex (`0x90`, `\x90`) and decimal (`144`) formats
* Finds and decodes Base64 blobs
* Handles noisy multi-line text and odd formatting
* De-duplicates with SHA-256
* Falls back to carving the whole binary if no text patterns hit
* Portable and lightweight - runs anywhere Python 3 is available

---

## Requirements

* Python 3.x
* No external dependencies

Tested and works out of the box on REMnux.

---

## Installation

```
git clone https://github.com/CloudyKhan/shellcode-carver.git
cd shellcode-carver
```

---

## Usage

```
python3 carver.py input_file.txt > shellcode.txt
```

Replace `input_file.txt` with any file that might have embedded shellcode. Source code, logs, scripts, binaries, etc. It should work with almost any extension as long as the contents are statically legible or decodable.

---

Then run the output in a shellcode emulator, for example:

```
scdbg /f shellcode.txt /s -1
```
## Disclaimer
This tool is for malware analysis and education. Shellcode can be harmful. Run in a safe, isolated lab VM. Use only on files you own or have permission to analyze. Please be responsible.  

(The author is not liable for damage or misuse)
