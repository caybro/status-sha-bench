#include <QtTest>

#include "go-sqlcipher-libtomcrypt/tomcrypt.h"

#include <openssl/aes.h>

namespace {
char *bin2hex(const unsigned char *bin, size_t len) {
  if (bin == nullptr || len == 0) return nullptr;

  char *out = (char*)malloc(len*2+1);
  if (!out) return nullptr;

  for (size_t i=0; i<len; i++) {
    out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
    out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
  }
  out[len*2] = '\0';

  return out;
}

QString uint32Array5_to_hex(uint32_t state[5]) {
  static constexpr auto fillChar = QLatin1Char('0');
  return QStringLiteral("%1%2%3%4%5")
      .arg(state[0], 8, 16, fillChar)
      .arg(state[1], 8, 16, fillChar)
      .arg(state[2], 8, 16, fillChar)
      .arg(state[3], 8, 16, fillChar)
      .arg(state[4], 8, 16, fillChar);
}

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

// AES-256
static constexpr unsigned char aes_key_24[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

static constexpr unsigned char aes_ct_24[] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                                              0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

// AES-512
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

  QTest::newRow("AES-256") <<
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
    unsigned char tmp[2][16]; // temp results
    symmetric_key key;
    zeromem(&key, sizeof(key));
    QCOMPARE(rijndael_setup((const unsigned char *)testKey.constData(), testKey.length(), 0, &key), CRYPT_OK);
    QCOMPARE(rijndael_ecb_encrypt((const unsigned char *)pt.constData(), tmp[0], &key), CRYPT_OK);
    QCOMPARE(rijndael_ecb_decrypt(tmp[0], tmp[1], &key), CRYPT_OK);
    QCOMPARE(XMEMCMP(tmp[0], (unsigned char *)ct.constData(), 16), 0);
    QCOMPARE(XMEMCMP(tmp[1], (unsigned char *)pt.constData(), 16), 0);
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
}

QTEST_APPLESS_MAIN(AesBench)

#include "tst_aesbench.moc"
