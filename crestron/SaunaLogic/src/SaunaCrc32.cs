using System;

namespace SunValleyHQ.Sauna
{
    internal static class SaunaCrc32
    {
        // Standard IEEE CRC32 (same as zlib/crc32), table-driven.
        private static readonly uint[] Table = BuildTable();

        private static uint[] BuildTable()
        {
            var table = new uint[256];
            const uint poly = 0xEDB88320u;
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++)
                {
                    c = ((c & 1u) != 0) ? (poly ^ (c >> 1)) : (c >> 1);
                }
                table[i] = c;
            }
            return table;
        }

        public static uint Compute(byte[] data, int offset, int count)
        {
            if (data == null) throw new ArgumentNullException("data");
            if (offset < 0 || count < 0 || offset + count > data.Length) throw new ArgumentOutOfRangeException();

            uint crc = 0x00000000u;
            for (int i = 0; i < count; i++)
            {
                var b = data[offset + i];
                crc = Table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
            }
            return crc;
        }
    }
}

