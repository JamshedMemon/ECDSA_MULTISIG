# ECDSA MultiSig Implementation

A Python implementation of ECDSA (Elliptic Curve Digital Signature Algorithm) multi-signature system. This tool allows multiple parties to sign messages, requiring a minimum number of signatures for validation.

## Features
- M-of-N multisignature scheme
- ECDSA using SECP256k1 curve
- Key pair generation
- Message signing and verification
- Prevention of duplicate signatures
- Detailed logging of signing process

## Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone [your-repository-url]
cd ecdsa-multisig
```

2. Install required dependencies:
```bash
pip install ecdsa
```

## Usage

### Basic Example
```python
from multisig import ECDSAMultiSig

# Create a 2-of-3 multisig (requires 2 signatures out of 3 participants)
multisig = ECDSAMultiSig(required_signatures=2, total_participants=3)

# Generate keypairs for participants
participants = [multisig.generate_keypair() for _ in range(3)]

# Add participants to the system
for participant in participants:
    multisig.add_participant(participant['public_key'])

# Create and hash a message
message = "Your message here"
message_hash = multisig.create_message_hash(message)

# Collect signatures
signatures = []
for i in range(2):  # Get signatures from first two participants
    signature = multisig.sign_message(message_hash, participants[i]['private_key'])
    signatures.append((signature, participants[i]['public_key']))

# Verify the signatures
is_valid = multisig.verify_message(message_hash, signatures)
print(f"Message is valid: {is_valid}")
```

### Running the Test Script
```bash
python test_multisig.py
```

## Project Structure
```
ecdsa-multisig/
├── multisig.py         # Main implementation
├── test_multisig.py    # Test script
└── README.md           # Documentation
```
