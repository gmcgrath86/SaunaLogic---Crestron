using System;
using System.Text;

namespace SunValleyHQ.Sauna
{
    internal static class SaunaCrypto
    {
        public static byte[] Aes128EcbEncrypt(string localKeyAscii, byte[] plaintext)
        {
            if (string.IsNullOrEmpty(localKeyAscii)) throw new ArgumentException("localKeyAscii");
            if (plaintext == null) throw new ArgumentNullException("plaintext");

            var key = Encoding.ASCII.GetBytes(localKeyAscii);
            if (key.Length != 16) throw new ArgumentException("localKey must be 16 ASCII bytes");
            return SaunaAes128EcbPkcs7.Encrypt(key, plaintext);
        }

        public static byte[] Aes128EcbDecrypt(string localKeyAscii, byte[] ciphertext)
        {
            if (string.IsNullOrEmpty(localKeyAscii)) throw new ArgumentException("localKeyAscii");
            if (ciphertext == null) throw new ArgumentNullException("ciphertext");

            var key = Encoding.ASCII.GetBytes(localKeyAscii);
            if (key.Length != 16) throw new ArgumentException("localKey must be 16 ASCII bytes");
            return SaunaAes128EcbPkcs7.Decrypt(key, ciphertext);
        }
    }
}

