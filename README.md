# AES Encryption and Decryption in Python

This repository demonstrates how to perform AES encryption and decryption of card details in Python using CBC mode. It includes padding with PKCS7 and base64 encoding/decoding for secure data handling.

## Prerequisites

- Python 3.x installed on your system.

## Code Overview

- CardDetails Class: Represents the structure of card details.
- Padding and Unpadding Functions: pad_pkcs7 for padding data and unpad_pkcs7 for removing padding.
- Encryption Function: encrypt for encrypting data using AES in CBC mode.
- Decryption Function: decrypt for decrypting data encrypted with AES in CBC mode.

## Setup

1. **Install Dependencies**

   Ensure you have Composer installed. Run the following command to install the required libraries:

   ```bash
   composer require phpseclib/phpseclib

2. **Configuration**

    Update the following values in the Encryption class:

    key: The base64-encoded encryption key.
    iv: The base64-encoded initialization vector.

3. **Encryption & Decryption**

- Encrypt Data

```bash
    # Example base64-encoded IV and key
    iv = '4betVRpFIVwvbNLJwMszew=='  # base64 encoded IV
    key = 'NBiPLxlq0WWInT4Hob+glw=='  # base64 encoded key

    # Card details to be encrypted
    card_details = CardDetails(
        card_number="4456530000001096",
        expiry_month="30",  # Example expiry month
        expiry_year="50",
        pin="1111",
        cvv="111"
    )

    # Convert card details to JSON string
    card_details_json = json.dumps(card_details.__dict__, separators=(',', ':'))

    # Encrypt the card details
    encrypted_text = encrypt(card_details_json, key, iv)

    print(f"Encrypted Card Details: {encrypted_text}")

```

- Decrypt Data

    ```bash

    # Decrypt the card details to verify
    decrypted_text = decrypt(encrypted_text, key, iv)

    print(f"Decrypted Card Details: {decrypted_text}")


    ```

## Notes

- Ensure the key and IV are kept secure and not hard-coded in production environments.
- Compare your encryption settings (key, IV, mode) with those used in C# to ensure consistency.
- PKCS7 Padding: Implemented PKCS7 padding to ensure the plaintext aligns with the AES block size of 16 bytes. This is essential for AES encryption in CBC mode.
- Base64 Encoding: Both the key and IV are base64 decoded before use in encryption. The output from the encryption process is base64 encoded.
- Block Size Handling: The AES block size for CBC mode is 16 bytes. Padding ensures that the plaintext length is a multiple of this block size, which is crucial for proper encryption.
