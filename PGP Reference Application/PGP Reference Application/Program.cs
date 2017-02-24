using System;
using System.Diagnostics;
using System.IO;
using Org.BouncyCastle.Bcpg;
using PGP_Reference_Application.Keys;
using PGP_Reference_Application.PGPDecryption;
using PGP_Reference_Application.PGPEncryption;

namespace PGP_Reference_Application
{
    class Program
    {
        static private String _keyRingHome = @"C:\keys\Kleopatra";
        static private String publicKeyRingFilename = "pubring.gpg";
        static private String secretKeyRingFilename = "secring.gpg";
        static private String secretKeyRingPassphrase = "open1234";       

        static private String filePath = @"C:\\Keys\\Files";
        static private String originalInputFile = "PlainText.txt";
        static private String encryptedFile = "EncryptedData.txt";       
        static private String outputFile = "Original.txt";

        //Used for signing        
        static private HashAlgorithmTag sigHashAlgorithm = HashAlgorithmTag.Sha1;
        static private String signatureKeyUserId = "Gregory Soto <gregorysoto@github.com>";
        private static bool withIntegrityCheck = true;
        private static bool withArmor = false;

        //Used for compression        
        static private CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Zip;

        //Used for encryption      
        static private SymmetricKeyAlgorithmTag symmetricAlgorithm = SymmetricKeyAlgorithmTag.Aes128;        
        static private String publicKeyEncryptionUserId = "Gregory Soto <gregorysoto@github.com>";        

        static void Main(string[] args)
        {
            Program objPgp = new Program();

            if (Debugger.IsAttached != true)
            {
                _keyRingHome = Environment.GetEnvironmentVariable("GNUPGHOME");    
            }
            

            try
            {
                objPgp.Encryption();
                objPgp.Decryption();
                                
                Console.Read();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Something went wrong");
                Console.WriteLine(ex.Message);
                Console.Read();
            }
        }

        public void Encryption()
        {
            PgpEncryptionKeys encryptionKeys = new PgpEncryptionKeys(_keyRingHome + "\\" + publicKeyRingFilename, publicKeyEncryptionUserId, _keyRingHome + "\\" + secretKeyRingFilename, signatureKeyUserId, secretKeyRingPassphrase);

            PgpEncrypt encrypter = new PgpEncrypt(encryptionKeys, symmetricAlgorithm, compressionAlgorithm, sigHashAlgorithm);

            using (Stream outputStream = File.Create(filePath + "\\" + encryptedFile))
            {
                encrypter.EncryptAndSign(outputStream, new FileInfo(filePath + "\\" + originalInputFile), withArmor, withIntegrityCheck);
            }
            Console.WriteLine("Encryption Done !");
        }

        public void Decryption()
        {
            PGPDecrypt.Decrypt(filePath + "\\" + encryptedFile, _keyRingHome + "\\" + secretKeyRingFilename, secretKeyRingPassphrase, filePath + "\\" + outputFile, _keyRingHome + "\\" + publicKeyRingFilename);

            Console.WriteLine("Decryption Done");
        }
    }
}
