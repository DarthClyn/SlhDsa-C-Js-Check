## Overview

**SLH-DSA** (Secure Lightweight Hashing - Digital Signature Algorithm) is an advanced cryptographic hashing algorithm specifically designed for Proof-of-Work (PoW) blockchain networks. This repository contains a custom implementation of the **SLH-DSA** algorithm written in **C**, **Python** and **TypeScript**, tailored to support the Quranium blockchain ecosystem.

- **C** implementation can be located in the `C/` directory.
- **Python** implementation can be located in the `python/` directory.
- **TypeScript** implementation can be located in the `typescript/` directory.

## Compiling and Running the C implementation

Navigate to the `C/` directory and run:

```sh
make        # Compile the C program
./main      # Run the compiled executable
```

## Creating a virtual environment and Running the Python implementation

Navigate to the `python/` directory and run:

```sh
python3 -m venv .venv        # Create a virtual environment
source .venv/bin/activate    # Activate the virtual environment
python3 main.py              # Run the Python script
```

## Building and Running the TypeScript implementation

Navigate to the `typescript/` directory and run:

```sh
yarn install --save --save-exact  # Install dependencies with exact versions
yarn build                        # Compile all TypeScript (.ts) files into JavaScript (.js)
yarn start                        # Execute the compiled JavaScript files:
```
