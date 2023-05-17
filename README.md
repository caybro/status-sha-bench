# status-sha-bench
Simple test and benchmark for various SHA1 and AES implementations

The goal is to compare and benchmark various implementations of the [SHA1](https://en.wikipedia.org/wiki/SHA-1) hash algorithm and the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) cipher

Frameworks/APIs tested:
1. Qt 5.15 / [QCryptoGraphicHash](https://doc.qt.io/qt-5/qcryptographichash.html); plain C/C++
2. [libtomcrypt](https://github.com/libtom/libtomcrypt); plain C (some ASM but disabled); as used currently in https://github.com/status-im/go-sqlcipher
3. [OpenSSL](https://www.openssl.org/); C/ASM/intrinsics
4. [git-sha1](https://github.com/tinganho/linux-kernel/blob/master/lib/sha1.c); plain C; (as used in Linux kernel)
5. [nayuki](https://www.nayuki.io/page/fast-sha1-hash-implementation-in-x86-assembly); highly optimized C and ASM
6. intrinsics - using Intel [SHA](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html)/ARM [Neon](https://developer.arm.com/Architectures/Neon) extensions; C/ASM, highly optimized

7. and finally, **libtomcrypt_new** which replaces the C-based `sha1_compress` subroutine with optimized versions from `intrinsics` (SHA/Neon) plus a fallback from `nayuki` 

For AES:
1. [libtomcrypt](https://github.com/libtom/libtomcrypt); plain C (some ASM but disabled); as used currently in https://github.com/status-im/go-sqlcipher
2. [OpenSSL](https://www.openssl.org/); C/ASM/intrinsics

### Machine 1: Linux, AMD Ryzen 7 6800HS, 16 GB RAM

![image](https://github.com/caybro/status-sha-bench/assets/5377645/02b53a89-d817-4cc3-906d-560d223f4c45)

![image](https://github.com/caybro/status-sha-bench/assets/5377645/d1aaf9b3-2be7-401c-97aa-7d86041c85a8)


### CSV bench results
https://github.com/caybro/status-sha-bench/blob/b7cdcbf820cea75655cc110e2b41fa17cda4d38d/bench_results.csv?plain=1#L1-L15
