# Certificate Cloner

&#x20; &#x20;

## Overview

**Certificate Cloner** is a Python utility designed for cloning digital certificates from one Windows PE executable to another. It is built for **security researchers** and **developers** working in **controlled testing environments**.

> ⚠️ This tool is strictly intended for educational and research purposes.

---

## Features

* Extracts digital certificates from PE files.
* Clones certificates to a target executable.
* Validates PE file integrity.
* Saves certificates as `.cer` files for manual trust installation.
* Provides detailed debugging output.
* Instructions included for trusting certificates manually.

---

## Requirements

* Python 3.8 or higher

### Python Packages

Install required packages:

```bash
pip install -r requirements.txt
```

Required packages include:

* `pefile`
* `cryptography`

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/myexistences/CertificateCloner.git
cd CertificateCloner
pip install -r requirements.txt
```

---

## Usage

Run the script with three command-line arguments:

```bash
python CertificateCloner.py SourceFile.exe TargetFile.exe OutputFile.exe
```

### Example:

```bash
python CertificateCloner.py ClipUp.exe myapp.exe SignedApp.exe
```

### Operation Summary:

* Validates input files as PE executables.
* Extracts certificate from `SourceFile.exe`.
* Clones it to `OutputFile.exe`.
* Saves the certificate as `cloned_certificate.cer`.
* Displays debug info and trust instructions.

---

## Manual Certificate Installation (Windows)

To manually trust the cloned certificate:

1. Right-click `OutputFile.exe` > Properties > Digital Signatures tab.
2. Select the signature > Details > View Certificate > Install Certificate.
3. Choose 'Local Machine' > Next.
4. Select 'Place all certificates in the following store' > Browse.
5. Choose 'Trusted Root Certification Authorities' > OK > Next > Finish.

> ❗ Note: Cloned signatures may appear invalid due to hash mismatch. For valid signatures, re-sign using Microsoft's `signtool.exe`.

---

## Security Warning

> Adding unverified certificates to the Trusted Root store can pose serious security risks. Use this tool only in isolated and secure test environments.

* Never use this tool on production systems.
* Always verify the origin and intent of certificates.
* Cloning certificates without permission may violate laws or software agreements.

---

## Disclaimer

This tool is meant for educational purposes only. Unauthorized use of certificate cloning techniques may violate software licenses, intellectual property laws, or other regulations. The author disclaims any liability for misuse.

> **Use responsibly and only in environments where you have explicit permission.**

---

## Contributing

Contributions are welcome via pull requests or issues. Please ensure all changes are well-documented and tested.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

\*\*Made with ❤️ by \*\*[**@myexistences**](https://github.com/myexistences)
