using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using PGP_Reference_Application.Keys;

namespace PGP_Reference_Application.PGPEncryption
{
    public class PgpEncrypt
    {

        private readonly PgpEncryptionKeys _encryptionKeys;
        static private SymmetricKeyAlgorithmTag _symmetricAlgorithm;
        static private CompressionAlgorithmTag _compressionAlgorithm;
        static private HashAlgorithmTag _sigHashAlgorithmTag;

        private const int BufferSize = 0x10000; // should always be power of 2 

        /// <summary>

        /// Instantiate a new PgpEncrypt class with initialized PgpEncryptionKeys.

        /// </summary>

        /// <param name="encryptionKeys"></param>
        /// <param name="symmetricAlgorithm"></param>
        /// <param name="compressionAlgorithm"></param>
        /// <param name="sigHashAlgorithmTag"></param>

        /// <exception cref="ArgumentNullException">encryptionKeys is null</exception>

        public PgpEncrypt(PgpEncryptionKeys encryptionKeys, SymmetricKeyAlgorithmTag symmetricAlgorithm, CompressionAlgorithmTag compressionAlgorithm, HashAlgorithmTag sigHashAlgorithmTag)
        {

            if (encryptionKeys == null)

                throw new ArgumentNullException("encryptionKeys", "encryptionKeys is null.");

            _encryptionKeys = encryptionKeys;
            _symmetricAlgorithm = symmetricAlgorithm;
            _compressionAlgorithm = compressionAlgorithm;
            _sigHashAlgorithmTag = sigHashAlgorithmTag;

        }

        /// <summary>

        /// Encrypt and sign the file pointed to by unencryptedFileInfo and

        /// write the encrypted content to outputStream.

        /// </summary>

        /// <param name="outputStream">The stream that will contain the

        /// encrypted data when this method returns.</param>
        /// <param name="unencryptedFileInfo">The filename of the file to encrypt.</param> 
        /// <param name="withIntegrityCheck">Should it include a </param>       

        public void EncryptAndSign(Stream outputStream, FileInfo unencryptedFileInfo, bool withArmor, bool withIntegrityCheck)
        {

            if (outputStream == null)

                throw new ArgumentNullException("outputStream", "outputStream is null.");

            if (unencryptedFileInfo == null)

                throw new ArgumentNullException("unencryptedFileInfo", "unencryptedFileInfo is null.");

            if (!File.Exists(unencryptedFileInfo.FullName))

                throw new ArgumentException("File to encrypt not found.");            

            if (withArmor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))

            using (Stream compressedOut = ChainCompressedOut(encryptedOut))
            {

                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);

                using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))

                using (FileStream inputFile = unencryptedFileInfo.OpenRead())
                {

                    WriteOutputAndSign(compressedOut, literalOut, inputFile, signatureGenerator);

                }

            }

            if (withArmor)
            {
                outputStream.Close();    
            }
        }

        private static void WriteOutputAndSign(Stream compressedOut,

            Stream literalOut,

            FileStream inputFile,

            PgpSignatureGenerator signatureGenerator)
        {

            int length;

            byte[] buf = new byte[BufferSize];

            while ((length = inputFile.Read(buf, 0, buf.Length)) > 0)
            {

                literalOut.Write(buf, 0, length);

                signatureGenerator.Update(buf, 0, length);

            }

            signatureGenerator.Generate().Encode(compressedOut);

        }

        private Stream ChainEncryptedOut(Stream outputStream, bool withIntegrityCheck)
        {

            PgpEncryptedDataGenerator encryptedDataGenerator = 
                new PgpEncryptedDataGenerator(_symmetricAlgorithm, withIntegrityCheck,
                                              new SecureRandom());

            encryptedDataGenerator.AddMethod(_encryptionKeys.PublicKey);

            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);

        }

        private static Stream ChainCompressedOut(Stream encryptedOut)
        {

            PgpCompressedDataGenerator compressedDataGenerator =

                new PgpCompressedDataGenerator(_compressionAlgorithm);

            return compressedDataGenerator.Open(encryptedOut);

        }

        private static Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {

            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();

            return pgpLiteralDataGenerator.Open(compressedOut, PgpLiteralData.Binary, file);

        }

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
        {

            const bool isCritical = false;

            const bool isNested = false;

            PublicKeyAlgorithmTag tag = _encryptionKeys.SecretKey.PublicKey.Algorithm;

            PgpSignatureGenerator pgpSignatureGenerator =

                new PgpSignatureGenerator(tag, _sigHashAlgorithmTag);

            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, _encryptionKeys.PrivateKey);

            foreach (string userId in _encryptionKeys.SecretKey.PublicKey.GetUserIds())
            {

                PgpSignatureSubpacketGenerator subPacketGenerator =
                   new PgpSignatureSubpacketGenerator();

                subPacketGenerator.SetSignerUserId(isCritical, userId);

                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());

                // Just the first one!

                break;

            }

            pgpSignatureGenerator.GenerateOnePassVersion(isNested).Encode(compressedOut);

            return pgpSignatureGenerator;

        }

    }

}
