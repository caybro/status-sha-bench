#include <QtTest>

#include "go-sqlcipher-libtomcrypt/tomcrypt.h"

#include <openssl/aes.h>
#include <botan/aes.h>
#include "tiny-AES-c/aes.hpp"
#include "mbedtls/aes.h"

namespace {
static const auto s_benchmarkString(QByteArrayLiteral("The quick brown fox jumps over the lazy dog"));
//static const auto s_benchmarkString(QByteArray(""));

// plain AES test data

// AES-128
static constexpr unsigned char aes_key_16[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

static constexpr unsigned char aes_pt_16[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                              0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

static constexpr unsigned char aes_ct_16[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                              0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };

// AES-192
static constexpr unsigned char aes_key_24[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

static constexpr unsigned char aes_ct_24[] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                                              0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

// AES-256
static constexpr unsigned char aes_key_32[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

static constexpr unsigned char aes_ct_32[] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                                              0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
}

class AesBench : public QObject
{
  Q_OBJECT

 public:
  AesBench(QObject *parent = nullptr);
     ~AesBench() override = default;

 private slots:
  void initTestCase();
  void cleanup();
  void cleanupTestCase();

  void test_strings_data();
  void test_strings();

  void bench_tomcrypt_aes128_decrypt_string();
  void bench_openssl_aes128_decrypt_string();
  void bench_botan_aes128_decrypt_string();
  void bench_mbedtls_aes128_decrypt_string();

  void bench_tomcrypt_aes192_decrypt_string();
  void bench_openssl_aes192_decrypt_string();
  void bench_botan_aes192_decrypt_string();
  void bench_mbedtls_aes192_decrypt_string();

  void bench_tomcrypt_aes256_decrypt_string();
  void bench_openssl_aes256_decrypt_string();
  void bench_botan_aes256_decrypt_string();
  void bench_tiny_aes256_decrypt_string();
  void bench_mbedtls_aes256_decrypt_string();
};

AesBench::AesBench(QObject * parent)
    : QObject(parent)
{
}

void AesBench::initTestCase()
{
}

void AesBench::cleanup()
{
}

void AesBench::cleanupTestCase()
{
}

void AesBench::test_strings_data()
{
  QTest::addColumn<QByteArray>("testKey");
  QTest::addColumn<QByteArray>("pt"); // plain text (always the same in fact)
  QTest::addColumn<QByteArray>("ct"); // encrypted text

  QTest::newRow("AES-128") <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_key_16), sizeof(aes_key_16)) <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_pt_16), sizeof(aes_pt_16)) <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_ct_16), sizeof(aes_ct_16));

  QTest::newRow("AES-192") <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_key_24), sizeof(aes_key_24)) <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_pt_16), sizeof(aes_pt_16)) <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_ct_24), sizeof(aes_ct_24));

  QTest::newRow("AES-256") <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_key_32), sizeof(aes_key_32)) <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_pt_16), sizeof(aes_pt_16)) <<
      QByteArray::fromRawData(reinterpret_cast<const char*>(aes_ct_32), sizeof(aes_ct_32));
}

void AesBench::test_strings()
{
  QFETCH(QByteArray, testKey);
  QFETCH(QByteArray, pt);
  QFETCH(QByteArray, ct);

  {
    // test libtomcrypt AES (aka rijndael)
    unsigned char tmp[2][AES_BLOCK_SIZE]; // temp results
    symmetric_key key;
    zeromem(&key, sizeof(key));
    QCOMPARE(rijndael_setup((const unsigned char *)testKey.constData(), testKey.length(), 0, &key), CRYPT_OK);
    QCOMPARE(rijndael_ecb_encrypt((const unsigned char *)pt.constData(), tmp[0], &key), CRYPT_OK);
    QCOMPARE(rijndael_ecb_decrypt(tmp[0], tmp[1], &key), CRYPT_OK);
    QCOMPARE(XMEMCMP(tmp[0], (unsigned char *)ct.constData(), AES_BLOCK_SIZE), 0);
    QCOMPARE(XMEMCMP(tmp[1], (unsigned char *)pt.constData(), AES_BLOCK_SIZE), 0);
  }

  {
    // test OpenSSL AES
    AES_KEY key;
    QCOMPARE(AES_set_encrypt_key((const unsigned char *)testKey.constData(), testKey.length() * 8, &key), 0);
    unsigned char encResult[AES_BLOCK_SIZE];
    AES_ecb_encrypt((const unsigned char *)pt.constData(), encResult, &key, AES_ENCRYPT);
    QCOMPARE(XMEMCMP(encResult, ct.constData(), AES_BLOCK_SIZE), 0);

    QCOMPARE(AES_set_decrypt_key((const unsigned char *)testKey.constData(), testKey.length() * 8, &key), 0);
    unsigned char decResult[AES_BLOCK_SIZE];
    AES_ecb_encrypt((const unsigned char *)ct.constData(), decResult, &key, AES_DECRYPT);
    QCOMPARE(XMEMCMP(decResult, pt.constData(), AES_BLOCK_SIZE), 0);
  }

  {
    // test mbedTLS AES
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, (const unsigned char *)testKey.constData(), testKey.length()*8);
    unsigned char encResult[AES_BLOCK_SIZE];
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, (const unsigned char *)pt.constData(), encResult);
    QCOMPARE(XMEMCMP(encResult, (const unsigned char *)ct.constData(), AES_BLOCK_SIZE), 0);
    mbedtls_aes_setkey_dec(&ctx, (const unsigned char *)testKey.constData(), testKey.length()*8);
    unsigned char decResult[AES_BLOCK_SIZE];
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, encResult, decResult);
    QCOMPARE(XMEMCMP(decResult, (const unsigned char *)pt.constData(), AES_BLOCK_SIZE), 0);
    mbedtls_aes_free(&ctx);
  }
}

void AesBench::bench_tomcrypt_aes128_decrypt_string()
{
  unsigned char tmp[2][AES_BLOCK_SIZE]; // temp results
  symmetric_key key;
  zeromem(&key, sizeof(key));
  QCOMPARE(rijndael_setup(aes_key_16, sizeof(aes_key_16), 0, &key), CRYPT_OK);
  QCOMPARE(rijndael_ecb_encrypt(aes_pt_16, tmp[0], &key), CRYPT_OK);

  QBENCHMARK {
    rijndael_ecb_decrypt(tmp[0], tmp[1], &key);
  }

  QCOMPARE(XMEMCMP(tmp[0], aes_ct_16, AES_BLOCK_SIZE), 0);
  QCOMPARE(XMEMCMP(tmp[1], aes_pt_16, AES_BLOCK_SIZE), 0);
}

void AesBench::bench_openssl_aes128_decrypt_string()
{
  AES_KEY key;
  QCOMPARE(AES_set_encrypt_key(aes_key_16, sizeof(aes_key_16) * 8, &key), 0);
  unsigned char encResult[AES_BLOCK_SIZE];
  AES_ecb_encrypt(aes_pt_16, encResult, &key, AES_ENCRYPT);
  QCOMPARE(XMEMCMP(encResult, aes_ct_16, AES_BLOCK_SIZE), 0);

  QCOMPARE(AES_set_decrypt_key(aes_key_16, sizeof(aes_key_16) * 8, &key), 0);
  unsigned char decResult[AES_BLOCK_SIZE];

  QBENCHMARK {
    AES_ecb_encrypt(aes_ct_16, decResult, &key, AES_DECRYPT);
  }

  QCOMPARE(XMEMCMP(decResult, aes_pt_16, AES_BLOCK_SIZE), 0);
}

void AesBench::bench_botan_aes128_decrypt_string()
{
    Botan::AES_128 cipher;
    uint8_t encResult[cipher.block_size()];
    Botan::SymmetricKey key{aes_key_16, sizeof(aes_key_16)};
    cipher.set_key(key);
    cipher.encrypt_n(aes_pt_16, encResult, 1);
    QCOMPARE(XMEMCMP(encResult, aes_ct_16, cipher.block_size()), 0);
    uint8_t decResult[cipher.block_size()];

    QBENCHMARK {
      cipher.decrypt_n(encResult, decResult, 1);
    }

    QCOMPARE(XMEMCMP(decResult, aes_pt_16, cipher.block_size()), 0);
}

void AesBench::bench_mbedtls_aes128_decrypt_string()
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, aes_key_16, sizeof(aes_key_16)*8);
    unsigned char encResult[AES_BLOCK_SIZE];
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, aes_pt_16, encResult);
    QCOMPARE(XMEMCMP(encResult, aes_ct_16, AES_BLOCK_SIZE), 0);
    mbedtls_aes_setkey_dec(&ctx, aes_key_16, sizeof(aes_key_16)*8);
    unsigned char decResult[AES_BLOCK_SIZE];

    QBENCHMARK {
      mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, encResult, decResult);
    }

    QCOMPARE(XMEMCMP(decResult, aes_pt_16, AES_BLOCK_SIZE), 0);
    mbedtls_aes_free(&ctx);
}

void AesBench::bench_tiny_aes256_decrypt_string()
{
    AES_ctx ctx;
    AES_init_ctx(&ctx, aes_key_32);
    uint8_t encResult[AES_BLOCKLEN];
    memcpy(encResult, aes_pt_16, sizeof(aes_pt_16));
    AES_ECB_encrypt(&ctx, encResult);
    QCOMPARE(XMEMCMP(encResult, aes_ct_32, AES_BLOCKLEN), 0);

    uint8_t decResult[AES_BLOCKLEN];
    memcpy(decResult, encResult, sizeof(encResult));
    QBENCHMARK {
      AES_ECB_decrypt(&ctx, decResult);
    }
}

void AesBench::bench_tomcrypt_aes192_decrypt_string()
{
  unsigned char tmp[2][AES_BLOCK_SIZE]; // temp results
  symmetric_key key;
  zeromem(&key, sizeof(key));
  QCOMPARE(rijndael_setup(aes_key_24, sizeof(aes_key_24), 0, &key), CRYPT_OK);
  QCOMPARE(rijndael_ecb_encrypt(aes_pt_16, tmp[0], &key), CRYPT_OK);

  QBENCHMARK {
    rijndael_ecb_decrypt(tmp[0], tmp[1], &key);
  }

  QCOMPARE(XMEMCMP(tmp[0], aes_ct_24, AES_BLOCK_SIZE), 0);
  QCOMPARE(XMEMCMP(tmp[1], aes_pt_16, AES_BLOCK_SIZE), 0);
}

void AesBench::bench_openssl_aes192_decrypt_string()
{
  AES_KEY key;
  QCOMPARE(AES_set_encrypt_key(aes_key_24, sizeof(aes_key_24) * 8, &key), 0);
  unsigned char encResult[AES_BLOCK_SIZE];
  AES_ecb_encrypt(aes_pt_16, encResult, &key, AES_ENCRYPT);
  QCOMPARE(XMEMCMP(encResult, aes_ct_24, AES_BLOCK_SIZE), 0);

  QCOMPARE(AES_set_decrypt_key(aes_key_24, sizeof(aes_key_24) * 8, &key), 0);
  unsigned char decResult[AES_BLOCK_SIZE];

  QBENCHMARK {
    AES_ecb_encrypt(aes_ct_24, decResult, &key, AES_DECRYPT);
  }

  QCOMPARE(XMEMCMP(decResult, aes_pt_16, AES_BLOCK_SIZE), 0);
}

void AesBench::bench_botan_aes192_decrypt_string()
{
  Botan::AES_192 cipher;
  uint8_t encResult[cipher.block_size()];
  Botan::SymmetricKey key{aes_key_24, sizeof(aes_key_24)};
  cipher.set_key(key);
  cipher.encrypt_n(aes_pt_16, encResult, 1);
  QCOMPARE(XMEMCMP(encResult, aes_ct_24, cipher.block_size()), 0);
  uint8_t decResult[cipher.block_size()];

  QBENCHMARK {
    cipher.decrypt_n(encResult, decResult, 1);
  }

  QCOMPARE(XMEMCMP(decResult, aes_pt_16, cipher.block_size()), 0);
}

void AesBench::bench_mbedtls_aes192_decrypt_string()
{
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, aes_key_24, sizeof(aes_key_24)*8);
  unsigned char encResult[AES_BLOCK_SIZE];
  mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, aes_pt_16, encResult);
  QCOMPARE(XMEMCMP(encResult, aes_ct_24, AES_BLOCK_SIZE), 0);
  mbedtls_aes_setkey_dec(&ctx, aes_key_24, sizeof(aes_key_24)*8);
  unsigned char decResult[AES_BLOCK_SIZE];

  QBENCHMARK {
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, encResult, decResult);
  }

  QCOMPARE(XMEMCMP(decResult, aes_pt_16, AES_BLOCK_SIZE), 0);
  mbedtls_aes_free(&ctx);
}

void AesBench::bench_tomcrypt_aes256_decrypt_string()
{
  unsigned char tmp[2][AES_BLOCK_SIZE]; // temp results
  symmetric_key key;
  zeromem(&key, sizeof(key));
  QCOMPARE(rijndael_setup(aes_key_32, sizeof(aes_key_32), 0, &key), CRYPT_OK);
  QCOMPARE(rijndael_ecb_encrypt(aes_pt_16, tmp[0], &key), CRYPT_OK);

  QBENCHMARK {
    rijndael_ecb_decrypt(tmp[0], tmp[1], &key);
  }

  QCOMPARE(XMEMCMP(tmp[0], aes_ct_32, AES_BLOCK_SIZE), 0);
  QCOMPARE(XMEMCMP(tmp[1], aes_pt_16, AES_BLOCK_SIZE), 0);
}

void AesBench::bench_openssl_aes256_decrypt_string()
{
  AES_KEY key;
  QCOMPARE(AES_set_encrypt_key(aes_key_32, sizeof(aes_key_32) * 8, &key), 0);
  unsigned char encResult[AES_BLOCK_SIZE];
  AES_ecb_encrypt(aes_pt_16, encResult, &key, AES_ENCRYPT);
  QCOMPARE(XMEMCMP(encResult, aes_ct_32, AES_BLOCK_SIZE), 0);

  QCOMPARE(AES_set_decrypt_key(aes_key_32, sizeof(aes_key_32) * 8, &key), 0);
  unsigned char decResult[AES_BLOCK_SIZE];

  QBENCHMARK {
    AES_ecb_encrypt(aes_ct_32, decResult, &key, AES_DECRYPT);
  }

  QCOMPARE(XMEMCMP(decResult, aes_pt_16, AES_BLOCK_SIZE), 0);
}

void AesBench::bench_botan_aes256_decrypt_string()
{
  Botan::AES_256 cipher;
  uint8_t encResult[cipher.block_size()];
  Botan::SymmetricKey key{aes_key_32, sizeof(aes_key_32)};
  cipher.set_key(key);
  cipher.encrypt_n(aes_pt_16, encResult, 1);
  QCOMPARE(XMEMCMP(encResult, aes_ct_32, cipher.block_size()), 0);
  uint8_t decResult[cipher.block_size()];

  QBENCHMARK {
    cipher.decrypt_n(encResult, decResult, 1);
  }

  QCOMPARE(XMEMCMP(decResult, aes_pt_16, cipher.block_size()), 0);
}

void AesBench::bench_mbedtls_aes256_decrypt_string()
{
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, aes_key_32, sizeof(aes_key_32)*8);
  unsigned char encResult[AES_BLOCK_SIZE];
  mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, aes_pt_16, encResult);
  QCOMPARE(XMEMCMP(encResult, aes_ct_32, AES_BLOCK_SIZE), 0);
  mbedtls_aes_setkey_dec(&ctx, aes_key_32, sizeof(aes_key_32)*8);
  unsigned char decResult[AES_BLOCK_SIZE];

  QBENCHMARK {
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, encResult, decResult);
  }

  QCOMPARE(XMEMCMP(decResult, aes_pt_16, AES_BLOCK_SIZE), 0);
  mbedtls_aes_free(&ctx);
}

QTEST_APPLESS_MAIN(AesBench)

#include "tst_aesbench.moc"
