# Hard To Find Bugs Documentation

This directory contains documentation and analysis of **Hard To Find Bugs (HFBs)** identified during this project. Each bug has been investigated, and its corresponding fix is described. The goal of this section is to provide a comprehensive understanding of how these bugs were discovered, their nature, and how they were addressed, and a code snippet to try and form a pattern to improve testing methods against these edges low occurence exceptions.

### Key Components:

* **Bug List** :
  * A list of identified bugs is provided in the `HFBs.xlsx` or `HFBs.csv` file.
  * Each entry corresponds to a specific bug, with a vector for its main charasteristics.
* **Collection Directory** :
  * The `/Collection` folder contains explanations of how the bugs/vulnerabilities function, classified by the type of bug, and with a code snippet of the faulty code.

### Bug Categories:

The bugs are classified into the following categories, each documented in its corresponding Markdown file:

```
📂 Collection
├── CARRY_PROPAGATION.md
│   └── Details bugs related to carry propagation issues in cryptographic or numerical computations.
├── CRYPTO_STATE.md
│   └── Explains bugs linked to improper handling or maintenance of cryptographic states during execution.
├── IMPLEMENTATIONS.md
│   └── Highlights bugs originating from flawed implementations of algorithms or protocols.
├── INPUT_VALIDATION.md
│   └── Documents issues caused by inadequate input validation, leading to unexpected behavior or vulnerabilities.
├── PARAM_HANDLING.md
│   └── Describes bugs related to improper parameter handling, including missing, incorrect, or misused parameters.
├── SPECIAL_CASES.md
│   └── Focuses on bugs that arise in rare or edge-case scenarios not considered during standard development.
└── TIMING_ATTACKS.md
    └── Analyzes vulnerabilities that expose the system to timing-based side-channel attacks.
```

---
