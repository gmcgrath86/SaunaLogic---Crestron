using System;

namespace SunValleyHQ.Sauna
{
    internal static class SaunaTuyaFrame
    {
        public const uint Prefix = 0x000055AA;
        public const uint Tail = 0x0000AA55;

        public static void WriteU32BE(byte[] buf, int offset, uint value)
        {
            buf[offset + 0] = (byte)((value >> 24) & 0xFF);
            buf[offset + 1] = (byte)((value >> 16) & 0xFF);
            buf[offset + 2] = (byte)((value >> 8) & 0xFF);
            buf[offset + 3] = (byte)(value & 0xFF);
        }

        public static uint ReadU32BE(byte[] buf, int offset)
        {
            return (uint)(
                (buf[offset + 0] << 24) |
                (buf[offset + 1] << 16) |
                (buf[offset + 2] << 8) |
                (buf[offset + 3] << 0));
        }

        /// <summary>
        /// Frame length convention in captured SaunaLogic Tuya frames:
        /// - The length field (bytes 12..15) equals (payload bytes + CRC+tail bytes),
        ///   meaning total frame length is: total = 16 + lengthField.
        /// - CRC32 is computed over frame bytes excluding the last 8 bytes (CRC + tail).
        /// </summary>
        public static byte[] BuildFrame(uint seq, uint cmd, byte[] payload, byte[] payloadPrefix)
        {
            if (payload == null) payload = new byte[0];
            if (payloadPrefix == null) payloadPrefix = new byte[0];

            var payloadLen = payloadPrefix.Length + payload.Length;
            var lenField = (uint)(payloadLen + 8); // crc32 + tail
            var totalLen = 16 + (int)lenField;

            var frame = new byte[totalLen];
            WriteU32BE(frame, 0, Prefix);
            WriteU32BE(frame, 4, seq);
            WriteU32BE(frame, 8, cmd);
            WriteU32BE(frame, 12, lenField);

            // payload
            Buffer.BlockCopy(payloadPrefix, 0, frame, 16, payloadPrefix.Length);
            Buffer.BlockCopy(payload, 0, frame, 16 + payloadPrefix.Length, payload.Length);

            // CRC32(frame[:-8]) big-endian
            var crc = SaunaCrc32.Compute(frame, 0, frame.Length - 8);
            WriteU32BE(frame, frame.Length - 8, crc);

            // tail
            WriteU32BE(frame, frame.Length - 4, Tail);
            return frame;
        }

        public static bool TryParseOneFrame(byte[] buffer, int offset, int count, out int frameStart, out int frameLen)
        {
            frameStart = -1;
            frameLen = 0;
            if (buffer == null || count < 16) return false;

            // scan for prefix
            for (int i = offset; i <= offset + count - 16; i++)
            {
                if (buffer[i + 0] == 0x00 && buffer[i + 1] == 0x00 && buffer[i + 2] == 0x55 && buffer[i + 3] == 0xAA)
                {
                    var lenField = (int)ReadU32BE(buffer, i + 12);
                    var total = 16 + lenField;
                    if (total <= 0) continue;
                    if (i + total <= offset + count)
                    {
                        frameStart = i;
                        frameLen = total;
                        return true;
                    }
                }
            }
            return false;
        }
    }
}

