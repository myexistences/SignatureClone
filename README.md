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

## 🖼️ Signature Preview Example

After successful cloning, you should see a Digital Signature tab like this:

![Signature Preview](https://i.imgur.com/uVztFBp.png)

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

* Adding untrusted certificate
