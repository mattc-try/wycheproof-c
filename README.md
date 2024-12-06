14 tests failing on XdhJwk cases reason not found

# Wycheproof-C

Wycheproof-C is a C-based implementation of Google's Wycheproof Java library. This project focuses on testing public key schemes and digital signatures, utilizing Wycheproof's comprehensive set of test vectors to detect rare bugs and edge cases in OpenSSL or other cryptographic libraries.

## Goals of the Project

The main objective is to:

1. Implement public key schemes and digital signature verification with unit tests, Known Answer Tests (KATs), and timing tests.
2. Leverage Wycheproof vectors to identify low-occurrence and potentially dangerous bugs in OpenSSL or other C libraries.
3. Provide a modifiable framework that supports testing other C cryptographic libraries.
4. Enhance testing coverage for cryptographic implementations to detect subtle bugs that may not be caught by standard test suites.

---

## Features

- **Supported Schemes**: Implements tests for public key algorithms such as ECDH, RSA, XDH, and digital signature algorithms (ECDSA, DSA).
- **Test Types**:
  - Unit tests for functionality validation.
  - Timing tests to detect timing vulnerabilities.
  - Known Answer Tests (KATs) using Wycheproof vectors.
- **Performance-Oriented Choices**: JSON parsing is handled via pre-parsed header files to improve test execution speed.
- **Extensibility**: The framework can be adapted to test any other C cryptographic library by replacing the OpenSSL-specific parts.

---

# File Structure

Below is the simplified and schema-style representation of the file structure, focusing on the core components of the project:

```
Wycheproof-C/
├── outputs/                       # Contains logs and output files
│   ├──            
│   └── ...                        
│
├── parsed_vectors/                # Pre-parsed Wycheproof test vectors for C
│   ├── <algorithm>_vectors.h      # Header files for test vectors (e.g., ECDH, RSA, etc.)
│   └── ...                        
│
├── tests/                         # Main test implementations
│   ├── unit/                      # Unit tests
│   │   ├── ecdh_test.c            
│   │   ├── ecdsa_test.c           
│   │   ├── eckey_test.c           
│   │   └── ...                    
│   │
│   ├── vect/                      # Vector-based tests
│   │   ├── v_ecdh.c               # Vector test for ECDH
│   │   ├── v_signatures.c         # Vector test for digital signatures
│   │   ├── v_xdh.c                # Vector test for XDH
│   │   └── ...                    
│   │
│   └── ...                        
│
├── test.py                        # Python script to automate test execution
└── README.md                      # Project documentation
```

---

### Key Directories and Files

1. **`tests/`**  
   Houses all test implementations:
   - **Unit Tests**: Focus on individual cryptographic operations.
   - **Vector Tests**: Utilize Wycheproof vectors to test against specific algorithms.

2. **`test.py`**  
   A Python script for running all tests. Automates test execution for convenience.

3. **`outputs/`**  
   Stores output logs and reports, including details of failed tests. This directory helps in analyzing test results.

4. **`parsed_vectors/`**  
   Contains pre-parsed Wycheproof test vectors as C header files. These vectors are directly included in the C tests for speed and convenience.

---

## Getting Started

### Requirements

- **Dependencies**:
  - OpenSSL library for cryptographic operations.
  - Python (for parsing Wycheproof vectors and running `test.py`).

### Running Tests

1. Clone the repository, have openssl installed usually should be :)
2. You can reparse the vectors to ensure they are right
3. Automated Testing:
   Use `test.py` to run tests, it will directly give you the options:
   ```bash
   python3 test.py
   ```
4. You can of course run tests manually if that's faster for you and if using another library then openssl, or a new build.
    ```bash
    gcc xdh_test.c -o outputs/xdh_test -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
    ```
    Will add more stuff for this later
    


---

## Limitations and Notes

1. **Development Stage**:  
   This project is under active development. Some features may not be fully functional, and there might be inconsistencies in code structure and behavior.

2. **Experience**:  
   This is a project by an undergraduate student, I don't consider myself an experienced cryptographer or programmer. 

3. **OpenSSL Specific**:  
   The current implementation is tailored for OpenSSL. However, the design will allow for modification to support other cryptographic libraries.

---

## Contributing

Contributions to improve the code, fix bugs, and extend functionality are welcome. Feel free to fork the repository, create a feature branch, and submit a pull request.

---

## Disclaimer

The code is provided as-is and may contain mistakes, it's a testing library.