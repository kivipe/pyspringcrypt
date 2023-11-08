# pylint: disable=invalid-name, missing-function-docstring, missing-module-docstring
from unittest.mock import patch, Mock
from pytest import CaptureFixture
import pyspringcrypt


def test_encode(capsys: CaptureFixture[str]) -> None:
    mock_args = Mock()
    mock_args.command = "encrypt"
    mock_args.key = "my_key"
    mock_args.data = "plaintext"
    with patch("pyspringcrypt.parse_args") as mock_parser:
        mock_parser.return_value = mock_args
        pyspringcrypt.main()
    captured = capsys.readouterr()
    assert len(captured.out) >= 64


def test_decode(capsys: CaptureFixture[str]) -> None:
    mock_args = Mock()
    mock_args.command = "decrypt"
    mock_args.key = "my_key"
    mock_args.data = "e1cb487339e916bd97cabd821d782d25998b0aafdf0ba84eba7c97099d08d42a"
    with patch("pyspringcrypt.parse_args") as mock_parser:
        mock_parser.return_value = mock_args
        pyspringcrypt.main()
    captured = capsys.readouterr()
    assert captured.out == "plaintext\n"
