using System;

namespace SunValleyHQ.Sauna
{
    /// <summary>
    /// Minimal AES-128 ECB with PKCS#7 padding.
    ///
    /// Implemented to avoid using System.Security.Cryptography, which is blocked in some Crestron SIMPL# sandboxes.
    /// </summary>
    internal static class SaunaAes128EcbPkcs7
    {
        // AES S-box
        private static readonly byte[] SBox = new byte[256]
        {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
        };

        private static readonly byte[] InvSBox = new byte[256]
        {
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
        };

        private static readonly byte[] Rcon = new byte[11] { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36 };

        public static byte[] Encrypt(byte[] key16, byte[] plaintext)
        {
            if (key16 == null || key16.Length != 16) throw new ArgumentException("key16");
            if (plaintext == null) throw new ArgumentNullException("plaintext");

            var padded = Pkcs7Pad(plaintext, 16);
            var outBuf = new byte[padded.Length];
            var roundKeys = ExpandKey(key16);
            var block = new byte[16];

            for (int i = 0; i < padded.Length; i += 16)
            {
                Buffer.BlockCopy(padded, i, block, 0, 16);
                EncryptBlock(block, roundKeys);
                Buffer.BlockCopy(block, 0, outBuf, i, 16);
            }
            return outBuf;
        }

        public static byte[] Decrypt(byte[] key16, byte[] ciphertext)
        {
            if (key16 == null || key16.Length != 16) throw new ArgumentException("key16");
            if (ciphertext == null) throw new ArgumentNullException("ciphertext");
            if ((ciphertext.Length % 16) != 0) throw new ArgumentException("ciphertext must be multiple of 16");

            var outBuf = new byte[ciphertext.Length];
            var roundKeys = ExpandKey(key16);
            var block = new byte[16];

            for (int i = 0; i < ciphertext.Length; i += 16)
            {
                Buffer.BlockCopy(ciphertext, i, block, 0, 16);
                DecryptBlock(block, roundKeys);
                Buffer.BlockCopy(block, 0, outBuf, i, 16);
            }
            return Pkcs7Unpad(outBuf, 16);
        }

        private static byte[] Pkcs7Pad(byte[] data, int blockSize)
        {
            var pad = blockSize - (data.Length % blockSize);
            if (pad == 0) pad = blockSize;
            var outBuf = new byte[data.Length + pad];
            Buffer.BlockCopy(data, 0, outBuf, 0, data.Length);
            for (int i = data.Length; i < outBuf.Length; i++) outBuf[i] = (byte)pad;
            return outBuf;
        }

        private static byte[] Pkcs7Unpad(byte[] data, int blockSize)
        {
            if (data.Length == 0 || (data.Length % blockSize) != 0) return data;
            var pad = data[data.Length - 1];
            if (pad == 0 || pad > blockSize) return data;
            for (int i = data.Length - pad; i < data.Length; i++)
            {
                if (data[i] != pad) return data;
            }
            var outLen = data.Length - pad;
            var outBuf = new byte[outLen];
            Buffer.BlockCopy(data, 0, outBuf, 0, outLen);
            return outBuf;
        }

        private static byte[] ExpandKey(byte[] key)
        {
            // 11 round keys * 16 bytes = 176 bytes
            var w = new byte[176];
            Buffer.BlockCopy(key, 0, w, 0, 16);
            int bytesGenerated = 16;
            int rconIter = 1;
            var temp = new byte[4];
            while (bytesGenerated < 176)
            {
                Buffer.BlockCopy(w, bytesGenerated - 4, temp, 0, 4);
                if ((bytesGenerated % 16) == 0)
                {
                    // RotWord
                    var t = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = t;
                    // SubWord
                    temp[0] = SBox[temp[0]];
                    temp[1] = SBox[temp[1]];
                    temp[2] = SBox[temp[2]];
                    temp[3] = SBox[temp[3]];
                    // Rcon
                    temp[0] ^= Rcon[rconIter++];
                }
                for (int i = 0; i < 4; i++)
                {
                    w[bytesGenerated] = (byte)(w[bytesGenerated - 16] ^ temp[i]);
                    bytesGenerated++;
                }
            }
            return w;
        }

        private static void EncryptBlock(byte[] state, byte[] roundKeys)
        {
            AddRoundKey(state, roundKeys, 0);
            for (int round = 1; round <= 9; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, roundKeys, round * 16);
            }
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, roundKeys, 160);
        }

        private static void DecryptBlock(byte[] state, byte[] roundKeys)
        {
            AddRoundKey(state, roundKeys, 160);
            for (int round = 9; round >= 1; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, roundKeys, round * 16);
                InvMixColumns(state);
            }
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, roundKeys, 0);
        }

        private static void AddRoundKey(byte[] state, byte[] roundKeys, int offset)
        {
            for (int i = 0; i < 16; i++) state[i] ^= roundKeys[offset + i];
        }

        private static void SubBytes(byte[] s)
        {
            for (int i = 0; i < 16; i++) s[i] = SBox[s[i]];
        }

        private static void InvSubBytes(byte[] s)
        {
            for (int i = 0; i < 16; i++) s[i] = InvSBox[s[i]];
        }

        private static void ShiftRows(byte[] s)
        {
            // state is column-major (as typical AES implementation): indices:
            // [0 4 8 12]
            // [1 5 9 13]
            // [2 6 10 14]
            // [3 7 11 15]
            byte t;
            // row 1: shift left by 1
            t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
            // row 2: shift left by 2
            t = s[2]; s[2] = s[10]; s[10] = t;
            t = s[6]; s[6] = s[14]; s[14] = t;
            // row 3: shift left by 3 (right by 1)
            t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
        }

        private static void InvShiftRows(byte[] s)
        {
            byte t;
            // row 1: shift right by 1
            t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
            // row 2: shift right by 2
            t = s[2]; s[2] = s[10]; s[10] = t;
            t = s[6]; s[6] = s[14]; s[14] = t;
            // row 3: shift right by 3 (left by 1)
            t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
        }

        private static byte xtime(byte x)
        {
            return (byte)(((x << 1) ^ (((x >> 7) & 1) * 0x1B)) & 0xFF);
        }

        private static void MixColumns(byte[] s)
        {
            for (int c = 0; c < 4; c++)
            {
                int i = c * 4;
                byte a0 = s[i + 0], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
                byte t = (byte)(a0 ^ a1 ^ a2 ^ a3);
                byte u = a0;
                s[i + 0] = (byte)(a0 ^ t ^ xtime((byte)(a0 ^ a1)));
                s[i + 1] = (byte)(a1 ^ t ^ xtime((byte)(a1 ^ a2)));
                s[i + 2] = (byte)(a2 ^ t ^ xtime((byte)(a2 ^ a3)));
                s[i + 3] = (byte)(a3 ^ t ^ xtime((byte)(a3 ^ u)));
            }
        }

        private static void InvMixColumns(byte[] s)
        {
            for (int c = 0; c < 4; c++)
            {
                int i = c * 4;
                byte a0 = s[i + 0], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];

                byte u = xtime(xtime((byte)(a0 ^ a2)));
                byte v = xtime(xtime((byte)(a1 ^ a3)));
                a0 ^= u; a2 ^= u; a1 ^= v; a3 ^= v;

                s[i + 0] = a0; s[i + 1] = a1; s[i + 2] = a2; s[i + 3] = a3;
            }
            MixColumns(s);
        }
    }
}

