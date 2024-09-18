"""Randomised One-Time Pad encryption and decryption functions in Python."""
import random

charset = "abcdefghijklmnopqrstuvwxyz "

ciphertexts_hex = [
    "b51667c4ca3d0d4bbb98d00891cc7ff0ae1c8da807",
    "b54526c09e7c4859a98c800a9b9b2bb5f6488da807",
    "a5537585ca3a4456bed5c144879c6af6b3488da807",
    "bd446389992c4c5bbf8680129d9f62f7ba0d8da807",
    "b25926de852e4918ad9cd40c9b997fb5a518cebb42",
    "bf5768898b325457b490801086952be1be01dea807",
    "af4667ca8f2f0d55bb9ec5449d982bf0b71bd4a807",
    #"65677a6f2068736b6c766171776c6e737a7a796d646e696873"
]

# Convert the ciphertexts to byte arrays
ciphertexts = [bytes.fromhex(ct) for ct in ciphertexts_hex]

# Length of the ciphertexts
ct_length = len(ciphertexts[0])

# Initialize the key with None
key = [None] * ct_length

# ASCII value for space character
space_ascii = ord(' ')

# Determine the key
for i in range(ct_length):
    for ct in ciphertexts:
        potential_key_byte = ct[i] ^ space_ascii
        # Validate the potential key byte
        valid = all(
            97 <= (other_ct[i] ^ potential_key_byte) <= 122 or
            (other_ct[i] ^ potential_key_byte) == 32
            for other_ct in ciphertexts
        )
        if valid:
            key[i] = potential_key_byte
            break

# Decrypt all ciphertexts using the found key
print("Key:", key)

plaintexts = []
for ct in ciphertexts:
    decrypted_text = [
        chr(ct[i] ^ key[i]) if key[i] is not None else '¿'
        for i in range(ct_length)
    ]
    plaintexts.append(''.join(decrypted_text))

# Print the decrypted plaintexts
for i, pt in enumerate(plaintexts):
    print(f"Plaintext {chr(ord('a') + i)}: {pt}")

    ##########################################################################################################################################################
def main():
    """Demo usage of functions."""
    vector = "test message test message"
    encrypted = encrypt(vector)
    decrypted = decrypt(encrypted[0], encrypted[1])

    print("Test Vector: " + vector)
    print("OTP: " + encrypted[0])
    print("Encrypted (hex): " + encrypted[1])
    print("Decrypted: " + decrypted)


def encrypt(plaintext):
    """Encrypt plaintext value.

    Keyword arguments:
    plaintext -- the plaintext value to encrypt.
    """
    otp = "".join(random.choice(charset) for _ in range(len(plaintext)))
    result = ""

    for c, o in zip(plaintext.lower(), otp):
        result += charset[(charset.find(c) + charset.find(o)) % len(charset)]

    # Convert the encrypted text to hexadecimal
    encrypted_hex = "".join(format(ord(c), "02x") for c in result)

    return otp, encrypted_hex


def decrypt(otp, encrypted_hex):
    """Decrypt secret value.

    Keyword arguments:
    otp -- the one-time pad used when the secret value was encrypted.
    encrypted_hex -- the encrypted value as a hexadecimal string.
    """
    # Convert the hexadecimal string back to a character string
    encrypted_text = "".join(chr(int(encrypted_hex[i:i+2], 16)) for i in range(0, len(encrypted_hex), 2))

    result = ""

    for c, o in zip(encrypted_text, otp):
        result += charset[(charset.find(c) - charset.find(o)) % len(charset)]

    return result


if __name__ == "__main__":
    main()