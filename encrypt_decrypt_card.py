import json
from Crypto.Cipher import AES
import base64

class CardDetails:
    def __init__(self, card_number, expiry_month, expiry_year, pin, cvv):
        self.CardNumber = card_number
        self.ExpiryMonth = expiry_month
        self.ExpiryYear = expiry_year
        self.Pin = pin
        self.Cvv = cvv

def pad_pkcs7(data):
    """Apply PKCS7 padding."""
    block_size = AES.block_size
    padding_length = block_size - len(data) % block_size
    padding = chr(padding_length) * padding_length
    return data + padding

def unpad_pkcs7(data):
    """Remove PKCS7 padding."""
    padding_length = ord(data[-1])
    return data[:-padding_length]

def encrypt(plain_text, key, iv):
    # Decode the base64 key and iv to bytes
    cryptkey = base64.b64decode(key)
    iv_bytes = base64.b64decode(iv)
    
    # Create AES cipher in CBC mode
    cipher = AES.new(cryptkey, AES.MODE_CBC, iv_bytes)

    # Apply PKCS7 padding to the plaintext
    padded_plain_text = pad_pkcs7(plain_text)

    # Encrypt the padded plaintext
    encrypted_bytes = cipher.encrypt(padded_plain_text.encode('utf-8'))

    # Base64 encode the encrypted data
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt(cipher_text, key, iv):
    """Decrypt ciphertext using AES CBC mode."""
    cryptkey = base64.b64decode(key)
    iv_bytes = base64.b64decode(iv)
    
    cipher = AES.new(cryptkey, AES.MODE_CBC, iv_bytes)
    encrypted_bytes = base64.b64decode(cipher_text)
    padded_plain_text = cipher.decrypt(encrypted_bytes).decode('utf-8')
    return unpad_pkcs7(padded_plain_text)

if __name__ == "__main__":
    # Example base64-encoded IV and key
    iv = '4betVRpFIVwvbNLJwMszew=='  # base64 encoded IV
    key = 'NBiPLxlq0WWInT4Hob+glw=='  # base64 encoded key

    # Card details to be encrypted(Sample)
    card_details = CardDetails(
        card_number="4456530000001096",
        expiry_month="30",  
        expiry_year="50",
        pin="1111",
        cvv="111"
    )

    # Convert card details to JSON string
    card_details_json = json.dumps(card_details.__dict__, separators=(',', ':'))

    # Encrypt the card details
    encrypted_text = encrypt(card_details_json, key, iv)

    print(f"Encrypted Card Details: {encrypted_text}")

    # Decrypt the card details to verify
    decrypted_text = decrypt(encrypted_text, key, iv)

    print(f"Decrypted Card Details: {decrypted_text}")
