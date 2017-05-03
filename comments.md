# Comments

These are just internal comments taken during development.

# Trezor limits

In the function `trezor/python-trezor/trezorlib/client.py/encrypt_keyvalue(self, n, key, value, ask_on_encrypt=True, ask_on_decrypt=True, iv=b'')`
the primary input is `value`. The length of `value` must be a multiple of 16
(AES blocksize of 128 bits). It must be buffered to multiple-of-16-bytes if not.
The same number of bytes that go in, come out, as usual for AES.
E.g. The return of 144-bytes in, is 144-bytes out.
Performance for encrypt and decrypt are the same, as usual for AES.

# Crypto/Cipher/blockalgo.py limit

The function `Crypto/Cipher/blockalgo.py/encrypt()` the input is limited to 2G (2**31).

If a file larger than 2G is encrypted this exception is thrown
```
./TrezorSymmetricFileEncryption.py -t  4.4G.img # 4G input file
Traceback (most recent call last):
  File "./TrezorSymmetricFileEncryption.py", line 1093, in <module>
    doWork(trezor, settings, fileMap)
  File "./TrezorSymmetricFileEncryption.py", line 1051, in doWork
    convertFile(inputFile, fileMap)
  File "./TrezorSymmetricFileEncryption.py", line 1038, in convertFile
    encryptFile(inputFile, fileMap, False)
  File "./TrezorSymmetricFileEncryption.py", line 1012, in encryptFile
    fileMap.save(inputFile, obfuscate)
  File "/home/manfred/briefcase/workspace/src/github.com/8go/TrezorSymmetricFileEncryption/file_map.py", line 123, in save
    encrypted = self.encryptOuter(serialized, self.outerIv)
  File "/home/manfred/briefcase/workspace/src/github.com/8go/TrezorSymmetricFileEncryption/file_map.py", line 138, in encryptOuter
    return self.encrypt(plaintext, iv, self.outerKey)
  File "/home/manfred/briefcase/workspace/src/github.com/8go/TrezorSymmetricFileEncryption/file_map.py", line 146, in encrypt
    return cipher.encrypt(padded)
  File "/usr/lib/python2.7/dist-packages/Crypto/Cipher/blockalgo.py", line 244, in encrypt
    return self._cipher.encrypt(plaintext)
OverflowError: size does not fit in an int
```

In order to handle files larger than 2G, one would have to junk and reassemble to 2G junks before/after the `cipher.encrypt(padded)` call.

# Size limits

Currently files are limited to 2G minus a few bytes.
There is also a limit in the fileformat used by TrezorSymmetricFileEncryption.
It stores the data length as 4-bytes. So, if one would want to go beyond 4G one
would have to change the TrezorSymmetricFileEncryption storage file format
to store the data size as 8 bytes.

# Performance

AES is very fast.
Most files take less than a seconds but depends on disk speed, CPU, etc.
Encrypting/decrypting a 2G file took about 15 sec on a computer with a very slow disk but fast CPU.
Encryption time and decryption time are usually the same.

# To-do list

- [x] file obfuscation
- [ ] inner, 2-nd round encryption, new GUI button for it
- [x] add icon to PIN and passphrase GUIs
- [ ] add screenshots to README.md
- [ ] screenshots of v0.2alpha
- [x] make the image smaller on main window
- [ ] more Testing
- [ ] get help with getting the word out, anyone wants to spread hte word on Twitter, Reddit, with Trezor, etc.?
