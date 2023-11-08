# pylint: disable=invalid-name, missing-function-docstring, missing-module-docstring
import random
import string
from unittest.mock import patch, mock_open
import pytest
import pyspringcrypt


class Test_AESEncryptor:
    """Unit tests for AESEncryptor"""

    def test_encrypt_decrypt(self) -> None:
        """Test encrypt and decrypt"""
        for _ in range(100):
            plaintext = self._generate_random_string(4, 64)
            password = self._generate_random_string(4, 64)
            salt_hex = self._generate_random_hex_string(4, 32)
            mode = random.choice(["CBC", "GCM"])
            encryptor = pyspringcrypt.AESEncryptor(password, salt_hex, mode=mode)
            decryptor = pyspringcrypt.AESEncryptor(password, salt_hex, mode=mode)
            ciphertext = encryptor.encrypt(plaintext)
            assert decryptor.decrypt(ciphertext) == plaintext

    def test_encypted_by_spring_cli(self) -> None:
        """Test that we can decrypt a string that was encrypted by Spring boot CLI"""
        password = "qwerty1234asdf"
        ciphertext = (
            "006b629594579895463a0739eeb13fb28aeebcd9b47495"
            "980bca7ce7fe94a668a164b2e6ed085d2319d46f1973d25dab"
        )
        plaintext = "this_is_to_be_encrypted"
        decryptor = pyspringcrypt.AESEncryptor(password)
        assert decryptor.decrypt(ciphertext) == plaintext

    def test_key_from_file(self) -> None:
        with patch("builtins.open", mock_open(read_data="sekre7_password")):
            encryptor = pyspringcrypt.AESEncryptor("@password_file")
            decryptor = pyspringcrypt.AESEncryptor("sekre7_password")
        assert decryptor.decrypt(encryptor.encrypt("important_message")) == "important_message"

    def test_unknown_mode(self) -> None:
        with pytest.raises(ValueError):
            _ = pyspringcrypt.AESEncryptor("foobar", "deadbeef", mode="FOO")

    @staticmethod
    def _generate_random_string(min_length: int, max_length: int, characters: str = "") -> str:
        """Generate a random string between min and max"""
        length = random.randint(min_length, max_length)
        if length % 2 != 0:
            length += 1
        if characters == "":
            characters = string.ascii_letters + string.digits
        return "".join(random.choice(characters) for _ in range(length))

    def _generate_random_hex_string(self, min_length: int, max_length: int) -> str:
        """Generate a random hex string between min and max"""
        characters = "0123456789ABCDEF"
        return self._generate_random_string(min_length, max_length, characters)
