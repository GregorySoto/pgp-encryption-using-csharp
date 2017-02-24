using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PGP_Reference_Application.Keys
{
    public class PgpEncryptionKeys
    {

        public PgpPublicKey PublicKey { get; private set; }

        public PgpPrivateKey PrivateKey { get; private set; }

        public PgpSecretKey SecretKey { get; private set; }

        public PgpEncryptionKeys(string publicKeyPath, String publicKeyUserId, string secretKeyPath, String secretKeyUserId, string passPhrase)
        {

            if (!File.Exists(publicKeyPath))

                throw new ArgumentException("Public key file not found", "publicKeyPath");

            if (!File.Exists(secretKeyPath))

                throw new ArgumentException("Private key file not found", "privateKeyPath");

            if (String.IsNullOrEmpty(passPhrase))

                throw new ArgumentException("passPhrase is null or empty.", "passPhrase");

            PublicKey = ReadPublicKey(publicKeyPath, publicKeyUserId);

            SecretKey = ReadSecretKey(secretKeyPath, secretKeyUserId);

            PrivateKey = ReadPrivateKey(passPhrase);

        }    

        #region Public Key

        private PgpPublicKey ReadPublicKey(string publicKeyPath, string publicKeyUserId)
        {

            using (Stream keyIn = File.OpenRead(publicKeyPath))

            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {

                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                
                PgpPublicKey foundKey = GetPublicKeyByUserId(publicKeyRingBundle, publicKeyUserId);

                if (foundKey != null)

                    return foundKey;

            }

            throw new ArgumentException("No encryption key found in public key ring.");

        }

        private PgpPublicKey GetPublicKeyByUserId(PgpPublicKeyRingBundle publicKeyRingBundle, String publicKeyUserId)
        {
            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {

                PgpPublicKey key = kRing.GetPublicKeys()

                    .Cast<PgpPublicKey>()

                    .Where(k => k.IsEncryptionKey)

                    .FirstOrDefault();


                if (key != null)
                {
                    foreach (String userId in key.GetUserIds())
                    {
                        if (userId.Contains(publicKeyUserId))
                            return key;
                    }
                }
            }

            return null;
        }

        #endregion

        #region Secret Key

        private PgpSecretKey ReadSecretKey(string secretKeyPath, string secretKeyUserId)
        {

            using (Stream keyIn = File.OpenRead(secretKeyPath))

            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {

                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                
                PgpSecretKey foundKey = GetsecretKeyByUserId(secretKeyRingBundle, secretKeyUserId);

                if (foundKey != null)

                    return foundKey;

            }

            throw new ArgumentException("Can't find signing key in key ring.");

        }


        private PgpSecretKey GetsecretKeyByUserId(PgpSecretKeyRingBundle secretKeyRingBundle, String secretKeyUserId)
        {
            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {

                PgpSecretKey key = kRing.GetSecretKeys()

                    .Cast<PgpSecretKey>()

                    .Where(k => k.IsSigningKey)

                    .FirstOrDefault();


                if (key != null)
                {
                    foreach (String userId in key.UserIds)
                    {
                        if (userId.Contains(secretKeyUserId))
                            return key;
                    }
                }
            }

            return null;
        }

        #endregion

        #region Private Key

        private PgpPrivateKey ReadPrivateKey(string passPhrase)
        {

            PgpPrivateKey privateKey = SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());

            if (privateKey != null)

                return privateKey;

            throw new ArgumentException("No private key found in secret key.");

        }

        #endregion

    }
}