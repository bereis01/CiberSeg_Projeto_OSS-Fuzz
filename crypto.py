from Crypto.Cipher import AES


def aes_cbc_encrypt(key: str, IV: str, message: str):
    """
    Encryption function using AES in CBC mode.

    Arguments:
    - key (str): Hexadecimal string of the key.
    - IV (str): Hexadecimal string of the IV.
    - message (str): Message to be encrypted as a normal Python string.

    Returns:
    - cipher_text (bytes): Bytes object of the cipher text.
    """
    # Builds the necessary parameters.
    key = bytes.fromhex(key)
    IV = bytes.fromhex(IV)
    message = message.encode("ascii")

    # Pads the message.
    padding_amount = 16 - (len(message) % 16)
    message += bytes([padding_amount for _ in range(padding_amount)])

    # Encrypts the message block by block.
    cipher_text = IV  # The resulting cipher text begins with the IV
    previous_block = IV  # First previous block is IV
    cipher = AES.new(
        key, AES.MODE_ECB
    )  # ECB mode use in a single block = just the plain AES
    for i in range(0, len(message), 16):
        # XORs the block with the previous one and encrypts it.
        message_block = bytes(
            a ^ b for a, b in zip(previous_block, message[i : (i + 16)])
        )
        encrypted_block = cipher.encrypt(message_block)

        # Updates parameters for next block.
        cipher_text += encrypted_block
        previous_block = encrypted_block

    return cipher_text


def aes_cbc_decrypt(key: str, cipher_text: str):
    """
    Decryption function using AES in CBC mode.

    Arguments:
    - key (str): Hexadecimal string of the key.
    - cipher (str): Hexadecimal string of the cipher text.

    Returns:
    - message (bytes): Bytes object of the original message.
    """
    # Decodes the received parameters.
    key = bytes.fromhex(key)
    cipher_text = bytes.fromhex(cipher_text)

    # Decrypts the cipher text block by block.
    message = bytes()
    previous_block = cipher_text[0:16]  # First previous block is IV
    cipher = AES.new(
        key, AES.MODE_ECB
    )  # ECB mode use in a single block = just the plain AES
    for i in range(16, len(cipher_text), 16):
        # Decrypts the block and XORs it with the previous one.
        decrypted_block = cipher.decrypt(cipher_text[i : (i + 16)])
        message_block = bytes(a ^ b for a, b in zip(previous_block, decrypted_block))

        # Updates parameters for next block.
        message += message_block
        previous_block = cipher_text[i : (i + 16)]

    # Removes padding from original message.
    padding_amount = message[-1]
    message = message[0 : (len(message) - padding_amount)]

    return message
