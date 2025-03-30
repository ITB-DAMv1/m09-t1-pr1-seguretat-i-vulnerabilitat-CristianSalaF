using System.Security.Cryptography;
using System.Text;

namespace EncryptionProject
{
    /// <summary>
    /// Utils class that handles Encryption, Decryption, and Sha256 Hashing
    /// </summary>
    public static class EncryptionUtils
    {
        /// <summary>
        /// Encrypts the specified data using the provided RSA key information.
        /// After the data is processed, it immediately initializes it so it is not stored in memory.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="rsaKeyInfo">The RSA key information used for encryption.</param>
        /// <returns>The encrypted data as a byte array.</returns>
        public static byte[] Encrypt(string data, RSAParameters rsaKeyInfo)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaKeyInfo);
                rsaKeyInfo = new RSAParameters();
                var dataToEncrypt = Encoding.UTF8.GetBytes(data);
                return rsa.Encrypt(dataToEncrypt, false);
            }
        }

        /// <summary>
        /// Decrypts the specified data using the provided RSA key information.
        /// After the data is processed, it immediately initializes it so it is not stored in memory.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="rsaKeyInfo">The RSA key information used for decryption.</param>
        /// <returns>The decrypted data as a string.</returns>
        public static string Decrypt(byte[] data, RSAParameters rsaKeyInfo)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaKeyInfo);
                rsaKeyInfo = new RSAParameters();
                var decryptedData = rsa.Decrypt(data, false);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }

        /// <summary>
        /// Computes the SHA256 hash of the input data.
        /// After the data is processed, it immediately initializes it so it is not stored in memory.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>The SHA256 hash as a hexadecimal string.</returns>
        public static string ComputeSha256Hash(string rawData)
        {
            using (var sha256Hash = SHA256.Create())
            {
                var bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                rawData = null;
                var builder = new StringBuilder();
                foreach (var t in bytes)
                {
                    builder.Append(t.ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}