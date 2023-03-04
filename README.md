# Advanced_Encryption_Standard

This is an AES encryption and decryption project done during my time at the **Academy of Cryptography Techniques**


## Install

Install all package requirements

``` bash
$ pip install -r requirements.txt
```

## Usage
To use in command line mode
``` bash
$ python CLI.py
```

For use in GUI mode
``` bash
$ python GUI.py
```

## Fearture

- 128/192/256 bits Encryption/Decryption

## Testing data

- Plaintext: 0x00112233445566778899aabbccddeeff
- Key 128bit: 000102030405060708090a0b0c0d0e0f
  - Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
- Key 192bit: 000102030405060708090a0b0c0d0e0f1011121314151617
  - Ciphertext: dda97ca4864cdfe06eaf70a0ec0d7191
- Key 256bit: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  - Ciphertext: 8ea2b7ca516745bfeafc49904b496089


## License

The GNU General Public License Verion 3 (GNU v3). Please see [License File](LICENSE) for more information.
