# status-sha-bench
Simple test and benchmark for various SHA1 implementations

The goal is to compare and benchmark various implementations of the [SHA1](https://en.wikipedia.org/wiki/SHA-1) hash algorithm

### Machine 1: Linux, AMD Ryzen 7 6800HS, 16 GB RAM

### Strings
QCryptographicHash (sha1 dynamic): 0.00011 msecs per iteration (total: 59, iterations: 524288)

QCryptographicHash (sha1 static): 0.00013 msecs per iteration (total: 71, iterations: 524288)

libtomcrypt: 0.00013 msecs per iteration (total: 73, iterations: 524288)

openssl: 0.000046 msecs per iteration (total: 97, iterations: 2097152)

git-sha1: 0.000092 msecs per iteration (total: 97, iterations: 1048576)

nayuki: 0.000073 msecs per iteration (total: 77, iterations: 1048576)

sha1-intrinsics: 0.000034 msecs per iteration (total: 72, iterations: 2097152)

### File hash
QCryptographicHash(big file): 114 msecs per iteration (total: 116, iterations: 1)

libtomcrypt(big file): 181 msecs per iteration (total: 129, iterations: 1)

nayuki (big file): 93 msecs per iteration (total: 99, iterations: 1)

sha1-intrinsics(big file): 42 msecs per iteration (total: 87, iterations: 2)

### CSV bench results
https://github.com/caybro/status-sha-bench/blob/0f79ce6274edf94d1d1626a93a5983b50cc0b473/bench_results.csv?plain=1#L1-L11
