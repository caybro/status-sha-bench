#include <QtTest>

#include <QCryptographicHash>

#include <tomcrypt.h>

#include <openssl/sha.h>

#include "git-sha1/git-sha1.h"

#include "nayuki/bench-nayuki.h"

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

static const auto s_benchmarkString(QByteArrayLiteral("The quick brown fox jumps over the lazy dog"));
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
  QScopedPointer<char, QScopedPointerPodDeleter> actualResultNayuki(bin2hex((const unsigned char*)nayuki_hash, sizeof(nayuki_hash))); // autodelete the malloc'd memory
  qInfo() << "NAYUKI:" << input << expectedResult << actualResultNayuki.get();
  QEXPECT_FAIL("", "Nayuki doesn't pass validation!!!", Continue);
  QCOMPARE(actualResultNayuki.get(), expectedResult);
}

void Sha1Bench::bench_QCryptographicHash_sha1()
{
  QBENCHMARK {
    m_qt_sha1->reset();
    m_qt_sha1->addData(s_benchmarkString);
    const auto result =  m_qt_sha1->result();
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
  QBENCHMARK {
    hash_state md;
    unsigned char tmp[SHA_DIGEST_LENGTH];
    sha1_init(&md);
    sha1_process(&md, (const unsigned char*)s_benchmarkString.constData(), s_benchmarkString.length());
    sha1_done(&md, tmp);
  }
}

void Sha1Bench::bench_openssl_sha1()
{
  QBENCHMARK {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)s_benchmarkString.constData(), s_benchmarkString.length(), hash);
  }
}

QTEST_APPLESS_MAIN(Sha1Bench)

void Sha1Bench::bench_git_sha1()
{
  QBENCHMARK {
    blk_SHA_CTX sha1;
    unsigned char hashout[SHA_DIGEST_LENGTH];
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

#include "tst_sha1bench.moc"
