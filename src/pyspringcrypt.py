"""Python native replacement for Spring Boot CLI encrypt and decrypt commands"""
import binascii
import argparse
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad


class AESEncryptor:
    """This class creates encryptor that replicates AES functions from Spring Boot CLI"""

    def __init__(self, password: str, salt_hex: str = "deadbeef", mode: str = "CBC"):
        self.key = self._derive_key(password, salt_hex)
        self.mode = mode
        self.block_size = AES.block_size
        self.iv_length = 16
        if mode == "CBC":
            self.cipher_mode = AES.MODE_CBC
        elif mode == "GCM":
            self.cipher_mode = AES.MODE_GCM  # type: ignore
        else:
            raise ValueError("Invalid mode. Supported modes are 'CBC' and 'GCM'.")

    def _derive_key(self, password: str, salt_hex: str) -> bytes:
        if password[0] == "@":
            password_file = password[1:]
            with open(password_file, "r", encoding="utf-8") as handle:
                password = handle.read()
        salt = binascii.unhexlify(salt_hex)
        # PBKDF2 to derive the key using the password and salt
        return PBKDF2(password, salt, dkLen=32, count=1024)  # 256-bit key

    def encrypt(self, plaintext: str) -> str:
        """Encrypt string and return IV followed by ciphertext as hex"""
        iv = get_random_bytes(self.iv_length)
        cipher = AES.new(self.key, self.cipher_mode, iv)
        ciphertext = cipher.encrypt(
            pad(plaintext.encode(), self.block_size) if self.mode == "CBC" else plaintext.encode()
        )
        return (iv + ciphertext).hex()

    def decrypt(self, ciphertext_hex: str) -> str:
        """Decrypt hex format ciphertext and return plaintext as string"""
        ciphertext = binascii.unhexlify(ciphertext_hex)
        iv = ciphertext[: self.iv_length]
        cipher = AES.new(self.key, self.cipher_mode, iv)
        decrypted = (
            unpad(cipher.decrypt(ciphertext[self.iv_length :]), self.block_size)  # noqa
            if self.mode == "CBC"
            else cipher.decrypt(ciphertext[self.iv_length :])  # noqa
        )
        return decrypted.decode()


def parse_args() -> argparse.Namespace:
    """Parse arguments for running with python -m pyspringcrypt"""
    parser = argparse.ArgumentParser(
        description="Python native replacement for Spring Boot CLI encrypt and decrypt commands"
    )
    subparsers = parser.add_subparsers(dest="command", help="sub-command help")

    parser_encrypt = subparsers.add_parser("encrypt", help="encrypt the data")
    parser_encrypt.add_argument("-k", "--key", required=True, help="encryption key")
    parser_encrypt.add_argument("data", help="data to encrypt")

    parser_decrypt = subparsers.add_parser("decrypt", help="decrypt the data")
    parser_decrypt.add_argument("-k", "--key", required=True, help="decryption key")
    parser_decrypt.add_argument("data", help="data to decrypt")

    args = parser.parse_args()
    if args.command not in ["encrypt", "decrypt"]:
        parser.print_help()
        sys.exit(1)
    return args


def main() -> None:
    """Main function for running with python -m"""

    args = parse_args()

    if args.command == "encrypt":
        encryptor = AESEncryptor(password=args.key)
        encrypted_data = encryptor.encrypt(args.data)
        print(encrypted_data)

    elif args.command == "decrypt":
        encryptor = AESEncryptor(password=args.key)
        decrypted_data = encryptor.decrypt(args.data)
        print(decrypted_data)


if __name__ == "__main__":
    main()
