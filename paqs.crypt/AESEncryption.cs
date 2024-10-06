using System.Security.Cryptography;
using System.Text;

namespace paqs.crypt
{

    public class AesEncryption
    {
        public static byte[] Encrypt(byte[] data, string password, byte[] salt, byte[] iv)
        {
            using (var aes = new AesManaged())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;

                var key = new Rfc2898DeriveBytes(password, salt, 10000);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }
        public static byte[] Decrypt(byte[] encryptedData, string password, byte[] salt, byte[] iv)
        {
            using (var aes = new AesManaged())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;

                var key = new Rfc2898DeriveBytes(password, salt, 10000);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream(encryptedData))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var reader = new BinaryReader(cs))
                    {
                        return reader.ReadBytes(encryptedData.Length);
                    }
                }
            }
        }
        public static byte[] GenerateRandomIV()
        {
            using (var aes = new AesManaged())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.GenerateIV();
                return aes.IV;
            }
        }

        public static byte[] HashSalt(string maskedsalt)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(maskedsalt));
            }
        }

        public static byte[] EncryptWithSha256Salt(byte[] data, string password, byte[] iv)
        {
            var salt = HashSalt(password);
            return Encrypt(data, password, salt, iv);
        }

        public static byte[] DecryptWithSha256Salt(byte[] encryptedData, string password, byte[] iv)
        {
            var salt = HashSalt(password);
            return Decrypt(encryptedData, password, salt, iv);
        }
    }
}
