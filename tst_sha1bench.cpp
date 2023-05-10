#include <QtTest>

#include <QCryptographicHash>

#include <tomcrypt.h>

#include <openssl/sha.h>

#include "git-sha1/git-sha1.h"

#include "nayuki/bench-nayuki.h"

#include "sha-intrinsics/sha1.h"

#include <memory>

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

QString uint32Array5_to_hex(uint32_t state[STATE_LEN]) {
  static constexpr auto fillChar = QLatin1Char('0');
  return QStringLiteral("%1%2%3%4%5")
      .arg(state[0], 8, 16, fillChar)
      .arg(state[1], 8, 16, fillChar)
      .arg(state[2], 8, 16, fillChar)
      .arg(state[3], 8, 16, fillChar)
      .arg(state[4], 8, 16, fillChar);
}

/* Full message intrinsics hasher */
void intrr_sha1_hash(const uint8_t message[], size_t len, uint32_t hash[STATE_LEN]) {
  hash[0] = UINT32_C(0x67452301);
  hash[1] = UINT32_C(0xEFCDAB89);
  hash[2] = UINT32_C(0x98BADCFE);
  hash[3] = UINT32_C(0x10325476);
  hash[4] = UINT32_C(0xC3D2E1F0);

  size_t off;
  for (off = 0; len - off >= BLOCK_LEN; off += BLOCK_LEN)
    sha1_process_x86(hash, &message[off], BLOCK_LEN);

  uint8_t block[BLOCK_LEN] = {0};
  size_t rem = len - off;
  memcpy(block, &message[off], rem);

  block[rem] = 0x80;
  rem++;
  if (BLOCK_LEN - rem < LENGTH_SIZE) {
    sha1_process_x86(hash, block, sizeof(block));
    memset(block, 0, sizeof(block));
  }

  block[BLOCK_LEN - 1] = (uint8_t)((len & 0x1FU) << 3);
  len >>= 5;
  for (int i = 1; i < LENGTH_SIZE; i++, len >>= 8)
    block[BLOCK_LEN - 1 - i] = (uint8_t)(len & 0xFFU);
  sha1_process_x86(hash, block, sizeof(block));
}

static const auto s_benchmarkString(QByteArrayLiteral("The quick brown fox jumps over the lazy dog"));
//static const auto s_benchmarkString(QByteArray(""));
}

class Sha1Bench : public QObject
{
  Q_OBJECT

 public:
  Sha1Bench(QObject *parent = nullptr);
  ~Sha1Bench() override = default;

 private slots:
  void initTestCase();
  void cleanup();
  void cleanupTestCase();

  void test_strings_data();
  void test_strings();

  void bench_QCryptographicHash_sha1();
  void bench_QCryptographicHash_sha1_static();
  void bench_tomcrypt_sha1();
  void bench_openssl_sha1();
  void bench_git_sha1();
  void bench_nayuki_sha1();
  void bench_intrinsics_sha1();

 private:
  std::unique_ptr<QCryptographicHash> m_qt_sha1;
};

Sha1Bench::Sha1Bench(QObject * parent)
    : QObject(parent)
    , m_qt_sha1(std::make_unique<QCryptographicHash>(QCryptographicHash::Sha1))
{
}

void Sha1Bench::initTestCase()
{
}

void Sha1Bench::cleanup()
{
  m_qt_sha1->reset();
}

void Sha1Bench::cleanupTestCase()
{
}

void Sha1Bench::test_strings_data()
{
  QTest::addColumn<QByteArray>("input");
  QTest::addColumn<QByteArray>("expectedResult");

  // test data generated with `echo -n "<input_string>" | openssl sha1`
  QTest::newRow("empty") << QByteArrayLiteral("") << QByteArrayLiteral("da39a3ee5e6b4b0d3255bfef95601890afd80709");
  QTest::newRow("password") << QByteArrayLiteral("password") << QByteArrayLiteral("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
  QTest::newRow("fox") << QByteArrayLiteral("The quick brown fox jumps over the lazy dog") << QByteArrayLiteral("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
  QTest::newRow("lorem") << QByteArrayLiteral("Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aliquam erat volutpat.")  // sth > 64 bytes
                         << QByteArrayLiteral("fcf73dd818a87a17718b408b2834ac2a9eefbc60");
}

void Sha1Bench::test_strings()
{
  QFETCH(QByteArray, input);
  QFETCH(QByteArray, expectedResult);

  // test QCryptographicHash SHA1
  m_qt_sha1->addData(input);
  QCOMPARE(m_qt_sha1->result().toHex(), expectedResult);

  // test libtomcrypt SHA1
  hash_state md;
  unsigned char tmp[SHA_DIGEST_LENGTH];
  sha1_init(&md);
  sha1_process(&md, (const unsigned char*)input.constData(), input.length());
  sha1_done(&md, tmp);
  QScopedPointer<char, QScopedPointerPodDeleter> actualResult(bin2hex(tmp, sizeof(tmp))); // autodelete the malloc'd memory
  QCOMPARE(actualResult.get(), expectedResult);

  //test openssl SHA1
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char*)input.constData(), input.length(), hash);
  QScopedPointer<char, QScopedPointerPodDeleter> actualResultSSL(bin2hex(hash, sizeof(hash))); // autodelete the malloc'd memory
  QCOMPARE(actualResultSSL.get(), expectedResult);

  // test nayuki
  uint32_t nayuki_hash[STATE_LEN];
  sha1_hash((const uint8_t *)input.constData(), input.length(), nayuki_hash);
  QString actualResultNayuki = uint32Array5_to_hex(nayuki_hash);
  QCOMPARE(actualResultNayuki, expectedResult);

  // test intrinsics
  uint32_t intr_hash[STATE_LEN];
  intrr_sha1_hash((const uint8_t *)input.constData(), input.length(), intr_hash);
  QString actualResultIntr = uint32Array5_to_hex(intr_hash);
  QCOMPARE(actualResultIntr, expectedResult);
}

void Sha1Bench::bench_QCryptographicHash_sha1()
{
  QBENCHMARK {
    m_qt_sha1->reset();
    m_qt_sha1->addData(s_benchmarkString);
    const auto result = m_qt_sha1->result();
  }
}

void Sha1Bench::bench_QCryptographicHash_sha1_static()
{
  QBENCHMARK {
    const auto result = QCryptographicHash::hash(s_benchmarkString, QCryptographicHash::Sha1);
  }
}

void Sha1Bench::bench_tomcrypt_sha1()
{
  hash_state md;
  unsigned char tmp[SHA_DIGEST_LENGTH];

  QBENCHMARK {
    sha1_init(&md);
    sha1_process(&md, (const unsigned char*)s_benchmarkString.constData(), s_benchmarkString.length());
    sha1_done(&md, tmp);
  }
}

void Sha1Bench::bench_openssl_sha1()
{
  unsigned char hash[SHA_DIGEST_LENGTH];

  QBENCHMARK {
    SHA1((const unsigned char*)s_benchmarkString.constData(), s_benchmarkString.length(), hash);
  }
}

void Sha1Bench::bench_git_sha1()
{
  blk_SHA_CTX sha1;
  unsigned char hashout[SHA_DIGEST_LENGTH];

  QBENCHMARK {
    blk_SHA1_Init(&sha1);
    blk_SHA1_Update(&sha1, s_benchmarkString.constData(), s_benchmarkString.length());
    blk_SHA1_Final(hashout, &sha1);
  }
}

void Sha1Bench::bench_nayuki_sha1()
{
  QBENCHMARK {
    uint32_t hash[STATE_LEN];
    sha1_hash((const uint8_t *)s_benchmarkString.constData(), s_benchmarkString.length(), hash);
  }
}

void Sha1Bench::bench_intrinsics_sha1()
{
  QBENCHMARK {
    uint32_t intr_hash[STATE_LEN];
    intrr_sha1_hash((const uint8_t *)s_benchmarkString.constData(), s_benchmarkString.length(), intr_hash);
  }
}

QTEST_APPLESS_MAIN(Sha1Bench)

#include "tst_sha1bench.moc"
