using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    public class Argon2Test : SimpleTest
    {
        private const int DEFAULT_OUTPUTLEN = 32;

        public override string Name
        {
            get { return "Argon2"; }
        }

        public override void PerformTest()
        {
            TestPermutations();
            TestVectorsFromInternetDraft();
            TestHash();
        }

        private void TestHash()
        {
            int version = Argon2Parameters.ARGON2_VERSION_10;

            // Multiple test cases for various input values
            RunHashTest(version, 2, 16, 1, "password", "somesalt",
                "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694", DEFAULT_OUTPUTLEN);

            RunHashTest(version, 2, 20, 1, "password", "somesalt",
                "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
                DEFAULT_OUTPUTLEN);

            RunHashTest(version, 2, 18, 1, "password", "somesalt",
                "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
                DEFAULT_OUTPUTLEN);

            RunHashTest(version, 2, 8, 1, "password", "somesalt",
                "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
                DEFAULT_OUTPUTLEN);
            RunHashTest(version, 2, 8, 2, "password", "somesalt",
                "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb", DEFAULT_OUTPUTLEN);
            RunHashTest(version, 1, 16, 1, "password", "somesalt",
                "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2", DEFAULT_OUTPUTLEN);
            RunHashTest(version, 4, 16, 1, "password", "somesalt",
                "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b", DEFAULT_OUTPUTLEN);
            RunHashTest(version, 2, 16, 1, "differentpassword", "somesalt",
                "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3", DEFAULT_OUTPUTLEN);
            RunHashTest(version, 2, 16, 1, "password", "diffsalt",
                "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497", DEFAULT_OUTPUTLEN);

            RunHashTest(version, 2, 16, 1, "password", "diffsalt",
                "1a097a5d1c80e579583f6e19c7e4763ccb7c522ca85b7d58143738e12ca39f8e6e42734c950ff2463675b97c37ba" +
                    "39feba4a9cd9cc5b4c798f2aaf70eb4bd044c8d148decb569870dbd923430b82a083f284beae777812cce18cdac68ee8ccef" +
                    "c6ec9789f30a6b5a034591f51af830f4",
                112);

            version = Argon2Parameters.ARGON2_VERSION_13;

            // Multiple test cases for various input values
            RunHashTest(version, 2, 16, 1, "password", "somesalt",
                "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
                DEFAULT_OUTPUTLEN);

            RunHashTest(version, 2, 20, 1, "password", "somesalt",
                "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41", DEFAULT_OUTPUTLEN);

            RunHashTest(version, 2, 18, 1, "password", "somesalt",
                "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb", DEFAULT_OUTPUTLEN);

            RunHashTest(version, 2, 8, 1, "password", "somesalt",
                "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f", DEFAULT_OUTPUTLEN);

            RunHashTest(version, 2, 8, 2, "password", "somesalt",
                "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61", DEFAULT_OUTPUTLEN);
            RunHashTest(version, 1, 16, 1, "password", "somesalt",
                "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf", DEFAULT_OUTPUTLEN);
            RunHashTest(version, 4, 16, 1, "password", "somesalt",
                "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b", DEFAULT_OUTPUTLEN);
            RunHashTest(version, 2, 16, 1, "differentpassword", "somesalt",
                "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee", DEFAULT_OUTPUTLEN);
            RunHashTest(version, 2, 16, 1, "password", "diffsalt",
                "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271", DEFAULT_OUTPUTLEN);
        }

        private void TestPermutations()
        {
            byte[] rootPassword = Encoding.UTF8.GetBytes("aac");
            byte[] buf;

            byte[][] salts = new byte[3][];

            salts[0] = new byte[16];
            salts[1] = new byte[16];
            salts[2] = new byte[16];
            for (int t = 0; t < 16; t++)
            {
                salts[1][t] = (byte)t;
                salts[2][t] = (byte)(16 - t);
            }

            //
            // Permutation, starting with a shorter array, same length then one longer.
            //
            for (int j = rootPassword.Length - 1; j < rootPassword.Length + 2; j++)
            {
                buf = new byte[j];

                for (int a = 0; a < rootPassword.Length; a++)
                {
                    for (int b = 0; b < buf.Length; b++)
                    {
                        buf[b] = rootPassword[(a + b) % rootPassword.Length];
                    }

                    List<byte[]> permutations = new List<byte[]>();

                    Permute(permutations, buf, 0, buf.Length - 1);

                    for (int i = 0; i != permutations.Count; i++)
                    {
                        byte[] candidate = permutations[i];
                        for (int k = 0; k != salts.Length; k++)
                        {
                            byte[] salt = salts[k];
                            byte[] expected = Generate(Argon2Parameters.ARGON2_VERSION_10, 1, 8, 2, rootPassword, salt, 32);
                            byte[] testValue = Generate(Argon2Parameters.ARGON2_VERSION_10, 1, 8, 2, candidate, salt, 32);

                            //
                            // If the passwords are the same for the same salt we should have the same string.
                            //
                            bool sameAsRoot = Arrays.AreEqual(rootPassword, candidate);
                            if (sameAsRoot != Arrays.AreEqual(expected, testValue))
                            {
                                Fail("expected same result");
                            }
                        }

                    }
                }
            }
        }

        // Test vectors from the RFC: https://datatracker.ietf.org/doc/rfc9106/
        private void TestVectorsFromInternetDraft()
        {
            byte[] password = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
            byte[] salt = new byte[] { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
            byte[] secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };
            byte[] ad = new byte[] { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04 };

            RunRfcTest(
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

            RunRfcTest(
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

            RunRfcTest(
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

        private void RunHashTest(int version, int iterations, int memory, int parallelism, string password, string salt, string expectedOutput, int tagLength)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i)
                .WithVersion(version)
                .WithIterations(iterations)
                .WithMemoryPowOfTwo(memory)
                .WithParallelism(parallelism)
                .WithSalt(saltBytes)
                .Build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.Init(parameters);

            byte[] result = new byte[tagLength];
            generator.GenerateBytes(passwordBytes, result);

            byte[] expectedOutputBytes = Hex.Decode(expectedOutput);
            if (!AreEqual(result, expectedOutputBytes))
            {
                Fail(String.Format("Result incorrect for test case with password: {0}, salt: {1}", password, salt));
            }
        }

        private void RunRfcTest(int version, int type, byte[] password, byte[] salt, byte[] secret, byte[] additional, int memoryCost, int iterations, int parallelism, int tagLength, byte[] expectedHash)
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

        private void Swap(byte[] buf, int i, int j)
        {
            byte b = buf[i];
            buf[i] = buf[j];
            buf[j] = b;
        }

        private void Permute(List<byte[]> permutation, byte[] a, int l, int r)
        {
            if (l == r)
            {
                permutation.Add(Arrays.Clone(a));
            }
            else
            {

                for (int i = l; i <= r; i++)
                {
                    // Swapping done
                    Swap(a, l, i);

                    // Recursion called
                    Permute(permutation, a, l + 1, r);

                    //backtrack
                    Swap(a, l, i);
                }
            }
        }

        private byte[] Generate(int version, int iterations, int memory, int parallelism,
                        byte[] password, byte[] salt, int outputLength)
        {
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i)
                .WithVersion(version)
                .WithIterations(iterations)
                .WithMemoryPowOfTwo(memory)
                .WithParallelism(parallelism)
                .WithSalt(salt)
                .Build();

            //
            // Set the password.
            //
            Argon2BytesGenerator gen = new Argon2BytesGenerator();

            gen.Init(parameters);

            byte[] result = new byte[outputLength];

            gen.GenerateBytes(password, result, 0, result.Length);
            return result;
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
