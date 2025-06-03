# SignatureClone

![Repo Size](https://img.shields.io/github/repo-size/myexistences/SignatureClone?style=flat-square)
![Stars](https://img.shields.io/github/stars/myexistences/SignatureClone?style=flat-square)
![Forks](https://img.shields.io/github/forks/myexistences/SignatureClone?style=flat-square)
![License](https://img.shields.io/github/license/myexistences/SignatureClone?style=flat-square)
![Views](https://komarev.com/ghpvc/?username=myexistences\&label=Repo%20Views\&color=blue\&style=flat-square)

---

## Overview

**SignatureClone** is a Python tool for cloning digital signatures (certificates) from one Windows PE executable to another. Built specifically for **cybersecurity researchers**, **malware analysts**, and **developers** working in **controlled testing environments**.

> ⚠️ This project is strictly for educational and testing purposes. Misuse is prohibited.

---

## ✨ Features

* 🧬 Clone digital certificates from one `.exe` file to another
* 📁 Export certificates as `.cer` files
* 🛡️ Preserve file structure and validate PE integrity
* 🔍 Debug-friendly logs and progress output
* 🖱️ Includes guide for manually trusting certificates in Windows

---

## 🔧 Requirements

* **Python** 3.8 or newer

### Install dependencies:

```bash
pip install -r requirements.txt
```

Packages:

* `pefile`
* `cryptography`

---

## 🚀 Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/myexistences/SignatureClone.git
cd SignatureClone
pip install -r requirements.txt
```

---

## ⚙️ Usage

Run the script with three arguments:

```bash
python CertificateCloner.py <SourceFile.exe> <TargetFile.exe> <OutputFile.exe>
```

### Example:

```bash
python CertificateCloner.py ClipUp.exe myapp.exe SignedApp.exe
```

### Summary:

* Validates PE structure
* Extracts certificate from `SourceFile.exe`
* Injects into `OutputFile.exe`
* Outputs debug info and `cloned_certificate.cer`

---

## 🖥️ Manually Trusting the Certificate (Windows)

1. Right-click `OutputFile.exe` → Properties → Digital Signatures
2. Click the signature → Details → View Certificate → Install Certificate
3. Choose **Local Machine** → Next
4. Choose **Trusted Root Certification Authorities**
5. Click OK → Next → Finish

> ❗ Windows will still show the signature as invalid unless re-signed with `signtool.exe`.

---

## 🔐 Security Warning

> Do not use in production. Use only in secure lab/test environments.

* Adding untrusted certificates to the system store is risky
* Cloning without permission may violate laws or licenses
* Always verify source files and use responsibly

---

## ⚖️ Disclaimer

This script is for **educational and ethical research** only. Misuse (e.g., spoofing, impersonation) may be illegal. The developer assumes no liability.

> Always use this tool in environments where you have **explicit permission**.

---

## 🤝 Contributing

Feel free to submit PRs or open issues! Make sure your changes include appropriate tests and documentation.

---

## 📄 License

MIT License. See [LICENSE](LICENSE).

---

**Crafted with 🛠️ by [@myexistences](https://github.com/myexistences)**
