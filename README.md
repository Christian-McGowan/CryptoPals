# CryptoPals Challenges in C (Sets 1 & 2)

This repository implements solutions in C for the first 12 CryptoPals challenges (Set 1 and the first half of Set 2). Each challenge lives in its own folder (`Challenge_1` through `Challenge_12`), containing the C source file (`C_n.c`) and, when applicable, an input file (`n.txt`).

---

## Table of Contents

1. [Overview](#overview)
2. [Repository Structure](#repository-structure)
3. [Prerequisites](#prerequisites)
4. [Compilation](#compilation)
5. [Running the Challenges](#running-the-challenges)
6. [Challenge Descriptions](#challenge-descriptions)
7. [Contributing](#contributing)
8. [License](#license)

---

## Overview

CryptoPals ([https://cryptopals.com](https://cryptopals.com)) provides hands-on cryptography challenges. This repository covers:

* **Set 1 (Challenges 1–8):** Byte & bit manipulation, encoding, XOR, AES-ECB decryption.
* **Set 2 (Challenges 9–12):** Padding, CBC decryption, and ECB/CBC detection.

Each folder `Challenge_n` contains:

* **`C_n.c`**: C implementation of the challenge.
* **`n.txt`** (optional): Sample input for the challenge.

---

## Repository Structure

```text
CryptoPals/
├── Challenge_1/
│   ├── C_1.c
│   └── 1.txt          # Input for Challenge 1
├── Challenge_2/
│   ├── C_2.c
│   └── 2.txt
├── Challenge_3/
│   ├── C_3.c
│   └── 3.txt
├── Challenge_4/
│   ├── C_4.c
│   └── 4.txt
├── Challenge_5/
│   ├── C_5.c
│   └── 5.txt
├── Challenge_6/
│   ├── C_6.c
│   └── 6.txt
├── Challenge_7/
│   └── C_7.c          # AES-ECB decryption; input hardcoded or provided via file
├── Challenge_8/
│   └── C_8.c          # ECB detection
├── Challenge_9/
│   └── C_9.c          # PKCS#7 padding
├── Challenge_10/
│   ├── C_10.c
│   └── 10.txt
├── Challenge_11/
│   └── C_11.c         # ECB/CBC oracle
├── Challenge_12/
│   └── C_12.c         # Byte-at-a-time ECB decryption
└── README.md
```

---

## Prerequisites

* **C Compiler** supporting C99 (e.g., `gcc`, `clang`).
* **OpenSSL development library** for AES functions (challenges 7, 10, 11, 12).

On Ubuntu/Debian:

```bash
sudo apt-get install build-essential libssl-dev
```

On macOS (with Homebrew):

```bash
brew install openssl
```

---

## Compilation

Navigate into each challenge folder and compile:

```bash
cd Challenge_n
# For challenges without OpenSSL dependencies:
gcc -std=c99 -Wall C_n.c -o C_n

# For challenges 7, 10, 11, 12 (AES/CBC):
gcc -std=c99 -Wall C_n.c -o C_n -lcrypto
```

Replace `n` with the challenge number (1–12).

---

## Running the Challenges

Each executable reads its input from the corresponding `n.txt` file (if present) or from a hardcoded filename. Example:

```bash
# From repository root
./Challenge_1/C_1 1.txt
./Challenge_2/C_2 2.txt
# Or, if the code reads stdin:
cat Challenge_3/3.txt | ./Challenge_3/C_3
```

Check the top comments in each `C_n.c` for precise usage and expected output.

---

## Challenge Descriptions

1. **Challenge\_1/C\_1.c** – Convert hex to Base64.
2. **Challenge\_2/C\_2.c** – Fixed XOR between two equal-length buffers.
3. **Challenge\_3/C\_3.c** – Single-byte XOR cipher decryption via frequency scoring.
4. **Challenge\_4/C\_4.c** – Identify and decrypt single-character XOR across multiple lines.
5. **Challenge\_5/C\_5.c** – Implement repeating-key XOR encryption.
6. **Challenge\_6/C\_6.c** – Break repeating-key XOR (Vigenère) using Hamming distance.
7. **Challenge\_7/C\_7.c** – Decrypt AES-128-ECB from Base64 input.
8. **Challenge\_8/C\_8.c** – Detect AES-ECB encrypted ciphertext.
9. **Challenge\_9/C\_9.c** – Implement and validate PKCS#7 padding.
10. **Challenge\_10/C\_10.c** – Decrypt AES-128-CBC given key and IV.
11. **Challenge\_11/C\_11.c** – ECB/CBC mode oracle detection.
12. **Challenge\_12/C\_12.c** – Byte-at-a-time ECB decryption.

---

## Contributing

Contributions are welcome! Fork the repo, add tests or optimizations, and submit a pull request.

---

## License

This project is released under the MIT License.
