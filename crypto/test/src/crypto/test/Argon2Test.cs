using NUnit.Framework;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System;

namespace Org.BouncyCastle.Crypto.Test
{
    public class Argon2Test: SimpleTest
    {
        public override string Name
        {
            get { return "Argon2"; }
        }

        // Test vectors from the RFC: https://datatracker.ietf.org/doc/rfc9106/
        private void TestVectorsFromInternetDraft()
        {
            byte[] password = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
            byte[] salt = new byte[] { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
            byte[] secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };
            byte[] ad = new byte[] { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04 };

            RunTest(
                Argon2Parameters.ARGON2_VERSION_13,
                Argon2Parameters.ARGON2_d,
                password,
                salt,
                secret,
                ad,
                32,
                3,
                4,
                32,
                new byte[] { 0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb }
            );

            RunTest(
                Argon2Parameters.ARGON2_VERSION_13,
                Argon2Parameters.ARGON2_d,
                password,
                salt,
                secret,
                ad,
                32,
                3,
                4,
                32,
                new byte[] { 0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb }
            );

            RunTest(
                Argon2Parameters.ARGON2_VERSION_13,
                Argon2Parameters.ARGON2_d,
                password,
                salt,
                secret,
                ad,
                32,
                3,
                4,
                32,
                new byte[] { 0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb }
            );
        }

        public override void PerformTest()
        {
            TestVectorsFromInternetDraft();
        }

        private void RunTest(int version, int type, byte[] password, byte[] salt, byte[] secret, byte[] additional, int memoryCost, int iterations, int parallelism, int tagLength, byte[] expectedHash)
        {
            Argon2Parameters parameters = new Argon2Parameters.Builder(type)
                .WithVersion(version)
                .WithSalt(salt)
                .WithSecret(secret)
                .WithAdditional(additional)
                .WithMemoryCost(memoryCost)
                .WithIterations(iterations)
                .WithParallelism(parallelism)
                .Build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.Init(parameters);

            byte[] result = new byte[tagLength];
            generator.GenerateBytes(password, result);

            if (!AreEqual(result, expectedHash))
            {
                Fail(String.Format("Result incorrect for test case with password: {0}, salt: {1}", Hex.ToHexString(password), Hex.ToHexString(salt)));
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
