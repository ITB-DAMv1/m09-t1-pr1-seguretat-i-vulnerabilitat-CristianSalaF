using System.Security.Cryptography;
using System.Text;

namespace EncryptionProject
{
    internal class Program
    {
        private static Dictionary<string, string> userDatabase = new Dictionary<string, string>();

        private const string MenuText = "Menú:";
        private const string RegisterOption = "1. Registrar-se";
        private const string VerifyDataOption = "2. Verificar Dades";
        private const string RSAEncryptionDecryptionOption = "3. Xifrat/Desxifrat RSA";
        private const string ExitOption = "0. Sortir";
        private const string ChooseOptionText = "Trieu una opció: ";
        private const string InvalidOptionText = "Opció no vàlida. Torneu-ho a provar.";
        private const string EnterUsernameText = "Introduïu el nom d'usuari: ";
        private const string EnterPasswordText = "Introduïu la contrasenya: ";
        private const string RegistrationSuccessText = "Registre complet. Hash: ";
        private const string DataVerificationSuccessText = "Verificació de dades correcta.";
        private const string DataVerificationFailedText = "Verificació de dades fallida.";
        private const string EnterTextToEncryptText = "Introduïu el text a xifrar: ";
        private const string InputTextTooLongText = "El text d'entrada és massa llarg. La longitud màxima és ";
        private const string EncryptedTextText = "Text xifrat: ";
        private const string DecryptedTextText = "Text desxifrat: ";

        static void Main(string[] args)
        {
            int choice = 99;
            do
            {
                Console.WriteLine(MenuText);
                Console.WriteLine(RegisterOption);
                Console.WriteLine(VerifyDataOption);
                Console.WriteLine(RSAEncryptionDecryptionOption);
                Console.WriteLine(ExitOption);
                Console.Write(ChooseOptionText);
                if (int.TryParse(Console.ReadLine(), out choice))
                {
                    switch (choice)
                    {
                        case 0:
                            return;
                        case 1:
                            Register();
                            break;
                        case 2:
                            VerifyData();
                            break;
                        case 3:
                            RSAEncryptionDecryption();
                            break;
                        default:
                            Console.WriteLine(InvalidOptionText);
                            break;
                    }
                }
                else
                {
                    Console.WriteLine(InvalidOptionText);
                }
            } while (choice != 0);
        }

        
        /// <summary>
        /// Registers a new user by taking a username and password, hashing them, and storing them in the user database.
        /// After the data is processed, it immediately initializes it so it is not stored in memory.
        /// </summary>
        private static void Register()
        {
            Console.Write(EnterUsernameText);
            var username = Console.ReadLine();
            Console.Write(EnterPasswordText);
            var password = Console.ReadLine();

            var hash = EncryptionUtils.ComputeSha256Hash(username + password);

            userDatabase[username] = hash;
            Console.WriteLine($"{RegistrationSuccessText}{hash}");
            
            username = null;
            password = null;
        }

        /// <summary>
        /// Verifies the user data by taking a username and password, hashing them, and comparing the hash with the stored hash in the user database.
        /// After the data is processed, it immediately initializes it so it is not stored in memory.
        /// </summary>
        private static void VerifyData()
        {
            Console.Write(EnterUsernameText);
            var username = Console.ReadLine();
            Console.Write(EnterPasswordText);
            var password = Console.ReadLine();

            var hash = EncryptionUtils.ComputeSha256Hash(username + password);

            if (userDatabase.ContainsKey(username) && userDatabase[username] == hash)
            {
                Console.WriteLine(DataVerificationSuccessText);
            }
            else
            {
                Console.WriteLine(DataVerificationFailedText);
            }

            username = null;
            password = null;
        }

        /// <summary>
        /// Encrypts and decrypts text using RSA encryption.
        /// Prompts the user to enter text, encrypts it, and then decrypts it.
        /// Initializes the text variable immediately after use.
        /// Displays the encrypted and decrypted text.
        /// </summary>
        private static void RSAEncryptionDecryption()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    Console.Write(EnterTextToEncryptText);
                    var text = Console.ReadLine();

                    int maxDataLength = (rsa.KeySize / 8) - 11;
                    if (Encoding.UTF8.GetByteCount(text) > maxDataLength)
                    {
                        Console.WriteLine($"{InputTextTooLongText}{maxDataLength} bytes.");
                        return;
                    }

                    var encryptedData = EncryptionUtils.Encrypt(text, rsa.ExportParameters(false));
                    text = null;
                    var decryptedData = EncryptionUtils.Decrypt(encryptedData, rsa.ExportParameters(true));

                    Console.WriteLine($"{EncryptedTextText}{Convert.ToBase64String(encryptedData)}");
                    Console.WriteLine($"{DecryptedTextText}{decryptedData}");
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}
