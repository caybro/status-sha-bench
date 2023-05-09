# status-sha-bench
Simple test and benchmark for various SHA1 implementations

The goal is to compare and benchmark various implementations of the [SHA1]([url](https://en.wikipedia.org/wiki/SHA-1)) hash algorithm

### Machine 1: Linux, AMD Ryzen 7 6800HS, 16 GB RAM

QCryptographicHash (sha1 dynamic): 0.00011 msecs per iteration (total: 59, iterations: 524288)

QCryptographicHash (sha1 static): 0.00013 msecs per iteration (total: 71, iterations: 524288)

libtomcrypt: 0.000097 msecs per iteration (total: 51, iterations: 524288)

openssl: 0.000046 msecs per iteration (total: 97, iterations: 2097152)

git-sha1: 0.000092 msecs per iteration (total: 97, iterations: 1048576)

nayuki: 0.000073 msecs per iteration (total: 77, iterations: 1048576)

sha1-intrinsics: 0.000034 msecs per iteration (total: 72, iterations: 2097152)
