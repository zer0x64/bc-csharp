using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Generators
{
    public class Argon2BytesGenerator
    {
        private Argon2Parameters parameters;

        public Argon2BytesGenerator() { }

        public void Init(Argon2Parameters parameters)
        {
            this.parameters = parameters;
        }

        public int GenerateBytes(byte[] password, byte[] output)
        {
            return GenerateBytes(password, output, 0, output.Length);
        }

        public int GenerateBytes(byte[] password, byte[] output, int outputOffset, int outputLength)
        {
            // Argon2 hashing logic
            Argon2 argon2 = new Argon2(parameters);
            argon2.Hash(password, output, outputOffset, outputLength);

            return outputLength;
        }
    }

    public class Argon2
    {
        private readonly Argon2Parameters parameters;
        private ulong[][] memory;

        private readonly byte[] tmpBlock = new byte[ARGON2_BLOCK_SIZE];
        private readonly int memorySize;
        private readonly int laneSize;
        private readonly int sliceSize;

        private const int ARGON2_BLOCK_SIZE = 1024;
        private const int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

        private const int ARGON2_ADDRESSES_IN_BLOCK = 128;
        private const int ARGON2_PREHASH_DIGEST_LENGTH = 64;
        private const int ARGON2_PREHASH_SEED_LENGTH = 72;
        private const int ARGON2_SYNC_POINTS = 4;
        private const int MIN_PARALLELISM = 1;
        private const int MAX_PARALLELISM = 16777216;
        private const int MIN_OUTLEN = 4;
        private const int MIN_ITERATIONS = 1;
        private const long M32L = 0xFFFFFFFFL;
        private static readonly byte[] ZERO_BYTES = new byte[4];

        public Argon2(Argon2Parameters parameters)
        {
            this.parameters = parameters;

            memorySize = 4 * parameters.Parallelism * (parameters.Memory / (4 * parameters.Parallelism));
            laneSize = memorySize / parameters.Parallelism;
            sliceSize = laneSize / ARGON2_SYNC_POINTS;
        }

        public void Hash(byte[] password, byte[] output, int outputOffset, int outputLength)
        {
            // Initialize internal state, memory blocks, etc.
            InitializeState(password, outputLength);

            // Perform the filling of memory blocks with Argon2 function logic
            FillMemory();

            // Apply finalization steps to produce the output hash
            FinalizeHash(output, outputOffset, outputLength);
        }

        private void InitializeState(byte[] password, int outputLength)
        {
            Blake2bDigest blake2b = new Blake2bDigest(ARGON2_PREHASH_DIGEST_LENGTH * 8);

            byte[] lanes = Pack.UInt32_To_LE((uint)parameters.Parallelism);
            byte[] outputLengthBytes = Pack.UInt32_To_LE((uint)outputLength);
            byte[] memory = Pack.UInt32_To_LE((uint)parameters.Memory);
            byte[] iterations = Pack.UInt32_To_LE((uint)parameters.Iterations);
            byte[] version = Pack.UInt32_To_LE((uint)parameters.Version);
            byte[] type = Pack.UInt32_To_LE((uint)parameters.Type);

            int passwordLength = password?.Length ?? 0;
            int saltLength = parameters.Salt?.Length ?? 0;
            int secretLength = parameters.Secret?.Length ?? 0; ;
            int additionalLength = parameters.Additional?.Length ?? 0;

            byte[] passwordLengthBytes = Pack.UInt32_To_LE((uint)passwordLength);
            byte[] saltLengthBytes = Pack.UInt32_To_LE((uint)saltLength);
            byte[] secretLengthBytes = Pack.UInt32_To_LE((uint)secretLength);
            byte[] additionalLengthBytes = Pack.UInt32_To_LE((uint)additionalLength);

            blake2b.BlockUpdate(lanes, 0, lanes.Length);
            blake2b.BlockUpdate(outputLengthBytes, 0, outputLengthBytes.Length);
            blake2b.BlockUpdate(memory, 0, memory.Length);
            blake2b.BlockUpdate(iterations, 0, iterations.Length);
            blake2b.BlockUpdate(version, 0, version.Length);
            blake2b.BlockUpdate(type, 0, type.Length);

            blake2b.BlockUpdate(passwordLengthBytes, 0, passwordLengthBytes.Length);
            if (passwordLength > 0)
            {
                blake2b.BlockUpdate(password, 0, password.Length);
            }

            blake2b.BlockUpdate(saltLengthBytes, 0, saltLengthBytes.Length);
            if (saltLength > 0)
            {
                blake2b.BlockUpdate(parameters.Salt, 0, parameters.Salt.Length);
            }

            blake2b.BlockUpdate(secretLengthBytes, 0, secretLengthBytes.Length);
            if (secretLength > 0)
            {
                blake2b.BlockUpdate(parameters.Secret, 0, parameters.Secret.Length);
            }

            blake2b.BlockUpdate(additionalLengthBytes, 0, additionalLengthBytes.Length);
            if (additionalLength > 0)
            {
                blake2b.BlockUpdate(parameters.Additional, 0, parameters.Additional.Length);
            }

            blake2b.DoFinal(tmpBlock, 0);
        }

        private void FillMemory()
        {
            memory = new ulong[memorySize][];

            for (int i = 0; i < memorySize; i++)
            {
                memory[i] = new ulong[ARGON2_BLOCK_SIZE / 8];
            }

            // Fill the first memory blocks with a hash of the initial state
            for (uint i = 0; i < parameters.Parallelism; i++)
            {
                Pack.UInt32_To_LE(i, tmpBlock, ARGON2_PREHASH_DIGEST_LENGTH + sizeof(int));

                byte[] tmpOut = new byte[ARGON2_BLOCK_SIZE];
                ExtendedHash(tmpBlock, 0, ARGON2_PREHASH_DIGEST_LENGTH + 2 * sizeof(int), tmpOut, 0, ARGON2_BLOCK_SIZE);

                Pack.LE_To_UInt64(tmpOut, 0, memory[i * laneSize]);
            }

            // Fill the second memory blocks with a hash of the initial state
            tmpBlock[ARGON2_PREHASH_DIGEST_LENGTH] = 1;
            for (uint i = 0; i < parameters.Parallelism; i++)
            {
                Pack.UInt32_To_LE(i, tmpBlock, ARGON2_PREHASH_DIGEST_LENGTH + sizeof(int));

                byte[] tmpOut = new byte[ARGON2_BLOCK_SIZE];
                ExtendedHash(tmpBlock, 0, ARGON2_PREHASH_DIGEST_LENGTH + 2 * sizeof(int), tmpOut, 0, ARGON2_BLOCK_SIZE);

                Pack.LE_To_UInt64(tmpOut, 0, memory[i * laneSize + 1]);
            }

            // Fill in the remaining blocks
            for (int pass = 0; pass < parameters.Iterations; pass++)
            {
                for (int slice = 0; slice < ARGON2_SYNC_POINTS; slice++)
                {
                    // TODO: Multithread this
                    for (int lane = 0; lane < parameters.Parallelism; lane++)
                    {
                        bool isIndependantAddressing = parameters.Type == Argon2Parameters.ARGON2_i ||
                            (parameters.Type == Argon2Parameters.ARGON2_id && pass == 0 && slice < 2);

                        // There is one working state per thread
                        FillerBlock filler = new FillerBlock();

                        if (isIndependantAddressing)
                        {
                            filler.InitializeIndependantAddressing(pass, lane, slice, memory.Length, parameters.Iterations, parameters.Type);
                        }

                        // We skip the first two blocks on first pass because they are already seeded
                        for (int currentBlock = pass == 0 && slice == 0 ? 2 : 0; currentBlock < laneSize / ARGON2_SYNC_POINTS; currentBlock++)
                        {
                            int currentBlockIndex = lane * laneSize + slice * sliceSize + currentBlock;
                            int lastBlockIndex;

                            if (currentBlockIndex % laneSize == 0)
                            {
                                /* Last block in this lane */
                                lastBlockIndex = currentBlockIndex + laneSize - 1;
                            }
                            else
                            {
                                /* Previous block */
                                lastBlockIndex = currentBlockIndex - 1;
                            }

                            ulong j;

                            if (isIndependantAddressing)
                            {
                                // Argon2i, or the independant part of Argon2id
                                int independantBlockAddress = currentBlock % ARGON2_ADDRESSES_IN_BLOCK;

                                if (independantBlockAddress == 0)
                                {
                                    filler.GenerateNextAddressingBlock();
                                }

                                j = filler.addressingOutputBlock[independantBlockAddress];
                            }
                            else
                            {
                                // Argon2d, or the dependant part of Argon2d
                                j = memory[lastBlockIndex][0];
                            }

                            int referenceBlockIndex = GetReferenceBlockIndex(pass, lane, slice, currentBlock, j);

                            // Apply G function (mixing function)
                            if (pass > 0 && parameters.Version == Argon2Parameters.ARGON2_VERSION_13)
                            {
                                filler.FillBlockWithXor(memory[lastBlockIndex], memory[referenceBlockIndex], memory[currentBlockIndex]);
                            }
                            else
                            {
                                filler.FillBlock(memory[lastBlockIndex], memory[referenceBlockIndex], memory[currentBlockIndex]);
                            }
                        }
                    }
                }
            }
        }

        private int GetReferenceBlockIndex(int pass, int lane, int slice, int currentBlock, ulong j)
        {
            int l;
            if (pass == 0 && slice == 0)
            {
                l = lane;
            }
            else
            {
                l = (int)((uint)(j >> 32) % parameters.Parallelism);
            }

            int startPosition, referenceAreaSize;

            if (pass == 0)
            {
                startPosition = 0;

                if (l == lane)
                {
                    /* The same lane => add current segment */
                    referenceAreaSize = slice * sliceSize + currentBlock - 1;
                }
                else
                {
                    /* pass == 0 && !sameLane => position.slice > 0*/
                    referenceAreaSize = slice * sliceSize + ((currentBlock == 0) ? (-1) : 0);
                }
            }
            else
            {
                startPosition = ((slice + 1) * sliceSize) % laneSize;

                if (l == lane)
                {
                    referenceAreaSize = laneSize - sliceSize + currentBlock - 1;
                }
                else
                {
                    referenceAreaSize = laneSize - sliceSize + ((currentBlock == 0) ? (-1) : 0);
                }
            }

            ulong relativePosition = j & 0xFFFFFFFFL;
            relativePosition = (relativePosition * relativePosition) >> 32;
            relativePosition = (ulong)referenceAreaSize - 1 - (((ulong)referenceAreaSize * relativePosition) >> 32);

            int x = (int)((ulong)startPosition + relativePosition) % laneSize;

            return l * laneSize + x;
        }

        private void FinalizeHash(byte[] output, int outputOffset, int outputLength)
        {
            // Accumulate on the output in the tmp block
            ulong[] accumulator = memory[laneSize - 1];

            for (int i = 1; i < parameters.Parallelism; i++)
            {
                for (int j = 0; j < ARGON2_QWORDS_IN_BLOCK; j++)
                {
                    accumulator[j] ^= memory[i * laneSize + laneSize - 1][j];
                }
            }

            Pack.UInt64_To_LE(accumulator, tmpBlock, 0);

            ExtendedHash(tmpBlock, 0, ARGON2_BLOCK_SIZE, output, outputOffset, outputLength);
        }

        private static void ExtendedHash(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset, int outputLength)
        {
            const int BLAKE2B_DIGEST_LENGTH = 64;
            const int HALF_BLAKE2B_DIGEST_LENGTH = BLAKE2B_DIGEST_LENGTH / 2;

            byte[] outputLengthBytes = BitConverter.GetBytes(outputLength);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(outputLengthBytes);
            }

            if (outputLength <= BLAKE2B_DIGEST_LENGTH)
            {
                Blake2bDigest blake = new Blake2bDigest(outputLength * 8);

                blake.BlockUpdate(outputLengthBytes, 0, outputLengthBytes.Length);
                blake.BlockUpdate(input, inputOffset, inputLength);

                blake.DoFinal(output, outputOffset);
            }
            else
            {
                Blake2bDigest blake = new Blake2bDigest(BLAKE2B_DIGEST_LENGTH * 8);
                byte[] outBuffer = new byte[BLAKE2B_DIGEST_LENGTH];

                // V1
                blake.BlockUpdate(outputLengthBytes, 0, outputLengthBytes.Length);
                blake.BlockUpdate(input, inputOffset, inputLength);

                blake.DoFinal(outBuffer, 0);

                Buffer.BlockCopy(outBuffer, 0, output, outputOffset, HALF_BLAKE2B_DIGEST_LENGTH);

                int rounds = (outputLength + 31) / 32 - 2;
                int outputPosition = outputOffset + HALF_BLAKE2B_DIGEST_LENGTH;

                for (int i = 2; i <= rounds; i++, outputPosition += HALF_BLAKE2B_DIGEST_LENGTH)
                {
                    // V2 to Vr
                    blake.BlockUpdate(outBuffer, 0, BLAKE2B_DIGEST_LENGTH);

                    blake.DoFinal(outBuffer, 0);

                    Buffer.BlockCopy(outBuffer, 0, output, outputPosition, HALF_BLAKE2B_DIGEST_LENGTH);
                }

                // Vr+1
                Blake2bDigest finalBlake = new Blake2bDigest((outputLength - 32 * rounds) * 8);
                finalBlake.BlockUpdate(outBuffer, 0, BLAKE2B_DIGEST_LENGTH);

                finalBlake.DoFinal(output, outputPosition);
            }
        }

        private class FillerBlock
        {
            public ulong[] rBlock = new ulong[ARGON2_ADDRESSES_IN_BLOCK];

            public ulong[] zBlock = new ulong[ARGON2_ADDRESSES_IN_BLOCK];

            public ulong[] addressingInputBlock;

            public ulong[] addressingOutputBlock;

            private const int BLAKE2_ROWS = 8;

            public void InitializeIndependantAddressing(int pass, int lane, int slice, int nBlocks, int nIterations, int type)
            {
                addressingInputBlock = new ulong[ARGON2_ADDRESSES_IN_BLOCK];
                addressingOutputBlock = new ulong[ARGON2_ADDRESSES_IN_BLOCK];

                addressingInputBlock[0] = (ulong)pass;
                addressingInputBlock[1] = (ulong)lane;
                addressingInputBlock[2] = (ulong)slice;
                addressingInputBlock[3] = (ulong)nBlocks;
                addressingInputBlock[4] = (ulong)nIterations;
                addressingInputBlock[5] = (ulong)type;

                if (pass == 0 && slice == 0)
                {
                    // Since currentBlock starts at 2 for the second pass, make sure we don't skip initialization
                    GenerateNextAddressingBlock();
                }
            }

            public void GenerateNextAddressingBlock()
            {
                addressingInputBlock[6]++;

                FillAddressingBlock(addressingInputBlock, addressingOutputBlock);
                FillAddressingBlock(addressingOutputBlock, addressingOutputBlock);
            }

            public void FillAddressingBlock(ulong[] input, ulong[] output)
            {
                CopyBlock(input, zBlock);
                ApplyBlake2(zBlock);
                XorBlocks(input, zBlock, output);
            }

            public void FillBlock(ulong[] x, ulong[] y, ulong[] output)
            {
                XorBlocks(x, y, rBlock);
                CopyBlock(rBlock, zBlock);
                ApplyBlake2(zBlock);
                XorBlocks(rBlock, zBlock, output);
            }

            public void FillBlockWithXor(ulong[] x, ulong[] y, ulong[] output)
            {
                XorBlocks(x, y, rBlock);
                CopyBlock(rBlock, zBlock);
                ApplyBlake2(zBlock);
                XorBlocksWith(rBlock, zBlock, output);
            }

            private static void ApplyBlake2(ulong[] input)
            {
                // Apply Blake2 based on rows
                for (int i = 0; i < BLAKE2_ROWS; i++)
                {
                    int i16 = 16 * i;
                    Blake2Round(input,
                        i16, i16 + 1,
                        i16 + 2, i16 + 3,
                        i16 + 4, i16 + 5,
                        i16 + 6, i16 + 7,
                        i16 + 8, i16 + 9,
                        i16 + 10, i16 + 11,
                        i16 + 12, i16 + 13,
                        i16 + 14, i16 + 15
                    );
                }

                // Apply Blake2 based on columns
                for (int i = 0; i < BLAKE2_ROWS; i++)
                {
                    int i2 = 2 * i;
                    Blake2Round(input,
                        i2, i2 + 1,
                        i2 + 16, i2 + 17,
                        i2 + 32, i2 + 33,
                        i2 + 48, i2 + 49,
                        i2 + 64, i2 + 65,
                        i2 + 80, i2 + 81,
                        i2 + 96, i2 + 97,
                        i2 + 112, i2 + 113
                    );
                }
            }

            private static void Blake2Round(
                ulong[] block,
                int v0, int v1, int v2, int v3,
                int v4, int v5, int v6, int v7,
                int v8, int v9, int v10, int v11,
                int v12, int v13, int v14, int v15)
            {
                Blake2F(block, v0, v4, v8, v12);
                Blake2F(block, v1, v5, v9, v13);
                Blake2F(block, v2, v6, v10, v14);
                Blake2F(block, v3, v7, v11, v15);

                Blake2F(block, v0, v5, v10, v15);
                Blake2F(block, v1, v6, v11, v12);
                Blake2F(block, v2, v7, v8, v13);
                Blake2F(block, v3, v4, v9, v14);
            }

            private static void Blake2F(ulong[] block, int a, int b, int c, int d)
            {
                Blake2QuarterRound(block, a, b, d, 32);
                Blake2QuarterRound(block, c, d, b, 24);
                Blake2QuarterRound(block, a, b, d, 16);
                Blake2QuarterRound(block, c, d, b, 63);
            }

            private static void Blake2QuarterRound(ulong[] block, int x, int y, int z, int s)
            {
                ulong a = block[x], b = block[y], c = block[z];

                a += b + 2 * (a & M32L) * (b & M32L);

                c = Longs.RotateRight(c ^ a, s);

                block[x] = a;
                block[z] = c;
            }

            private static void XorBlocks(ulong[] x, ulong[] y, ulong[] output)
            {
                for (int i = 0; i < ARGON2_ADDRESSES_IN_BLOCK; i++)
                {
                    output[i] = x[i] ^ y[i];
                }
            }

            private static void XorBlocksWith(ulong[] x, ulong[] y, ulong[] output)
            {
                for (int i = 0; i < ARGON2_ADDRESSES_IN_BLOCK; i++)
                {
                    output[i] ^= x[i] ^ y[i];
                }
            }

            private static void CopyBlock(ulong[] input, ulong[] output)
            {
                Buffer.BlockCopy(input, 0, output, 0, ARGON2_BLOCK_SIZE);
            }
        }
    }
}
