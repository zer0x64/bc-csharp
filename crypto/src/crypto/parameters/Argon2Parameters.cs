using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class Argon2Parameters
    {
        public const int ARGON2_d = 0x00;
        public const int ARGON2_i = 0x01;
        public const int ARGON2_id = 0x02;

        public const int ARGON2_VERSION_10 = 0x10;
        public const int ARGON2_VERSION_13 = 0x13;

        private const int DEFAULT_ITERATIONS = 3;
        private const int DEFAULT_MEMORY_COST = 12;
        private const int DEFAULT_LANES = 1;
        private const int DEFAULT_TYPE = ARGON2_i;
        private const int DEFAULT_VERSION = ARGON2_VERSION_13;

        public int Type { get; }
        public int Version { get; }
        public int Memory { get; }
        public int Iterations { get; }
        public int Parallelism { get; }
        public byte[] Salt { get; }
        public byte[] Secret { get; }
        public byte[] Additional { get; }

        private Argon2Parameters(Builder builder)
        {
            Type = builder.Type;
            Version = builder.Version;
            Memory = builder.Memory;
            Iterations = builder.Iterations;
            Parallelism = builder.Parallelism;
            Salt = builder.Salt;
            Secret = builder.Secret;
            Additional = builder.Additional;
        }

        public void Clear()
        {
            Arrays.Clear(Salt);
            Arrays.Clear(Secret);
            Arrays.Clear(Additional);
        }

        public class Builder
        {
            public int Type { get; private set; } = DEFAULT_TYPE;
            public int Version { get; private set; } = DEFAULT_VERSION;
            public int Memory { get; private set; } = 1 << DEFAULT_MEMORY_COST;
            public int Iterations { get; private set; } = DEFAULT_ITERATIONS;
            public int Parallelism { get; private set; } = DEFAULT_LANES;
            public byte[] Salt { get; private set; } 
            public byte[] Secret { get; private set; }
            public byte[] Additional { get; private set; }

            public Builder(int type) {
                WithType(type);
            }

            public Builder WithType(int type)
            {
                Type = type;
                return this;
            }

            public Builder WithVersion(int version)
            {
                Version = version;
                return this;
            }

            public Builder WithMemoryCost(int memory)
            {
                Memory = memory;
                return this;
            }

            public Builder WithIterations(int iterations)
            {
                Iterations = iterations;
                return this;
            }

            public Builder WithParallelism(int parallelism)
            {
                Parallelism = parallelism;
                return this;
            }

            public Builder WithSalt(byte[] salt)
            {
                Salt = (byte[])salt.Clone();
                return this;
            }

            public Builder WithSecret(byte[] secret)
            {
                Secret = (byte[])secret.Clone();
                return this;
            }

            public Builder WithAdditional(byte[] additional)
            {
                Additional = (byte[])additional.Clone();
                return this;
            }

            public Argon2Parameters Build()
            {
                return new Argon2Parameters(this);
            }

            public void Clear()
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(Salt);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(Secret);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(Additional);
#else
                Array.Clear(Salt, 0, Salt.Length);
                Array.Clear(Secret, 0, Secret.Length);
                Array.Clear(Additional, 0, Additional.Length);
#endif
            }
        }
    }
}
