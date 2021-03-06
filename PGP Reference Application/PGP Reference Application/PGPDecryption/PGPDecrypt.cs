﻿using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace PGP_Reference_Application.PGPDecryption
{
    public class PGPDecrypt
    {
        private const int BufferSize = 0x10000; // should always be power of 2    

        #region Decrypt

        /*
       * decrypt a given stream.
       */

        public static void Decrypt(string inputfile, string privateKeyFile, string passPhrase, string outputFile, String publicKeyFile)
        {
            if (!File.Exists(inputfile))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputfile));

            if (!File.Exists(privateKeyFile))
                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFile));

            if (String.IsNullOrEmpty(outputFile))
                throw new ArgumentNullException("Invalid Output file path.");

            using (Stream inputStream = File.OpenRead(inputfile))
            {
                using (Stream keyIn = File.OpenRead(privateKeyFile))
                {
                    using (Stream publicKeyIn = File.OpenRead(publicKeyFile))
                        Decrypt(inputStream, keyIn, passPhrase, outputFile, publicKeyIn);
                }
            }
        }

        /*
        * decrypt a given stream.
        */

        public static void Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase, string outputFile, Stream publicKeyStream)
        {
            try
            {
                bool deleteOutputFile = false;

                PgpEncryptedDataList enc;
                PgpObject o = null;
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;

                var pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                // find secret key
                var pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                if (pgpF != null)
                    o = pgpF.NextPgpObject();

                // the first object might be a PGP marker packet.
                if (o is PgpEncryptedDataList)
                    enc = (PgpEncryptedDataList)o;
                else
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

                // decrypt
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (sKey == null)
                    throw new ArgumentException("Secret key for message not found.");

                PgpObjectFactory plainFact = null;

                using (Stream clear = pbe.GetDataStream(sKey))
                {
                    plainFact = new PgpObjectFactory(clear);
                }

                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory of = null;

                    using (Stream compDataIn = cData.GetDataStream())
                    {
                        of = new PgpObjectFactory(compDataIn);
                    }

                    message = of.NextPgpObject();
                    if (message is PgpOnePassSignatureList)
                    {
                        PgpOnePassSignature ops = ((PgpOnePassSignatureList)message)[0];

                        PgpPublicKeyRingBundle pgpRing = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));

                        //USE THE BELOW TO CHECK FOR A FAILING SIGNATURE VERIFICATION. 
                        //THE CERTIFICATE MATCHING THE KEY ID MUST BE IN THE PUBLIC KEY RING.
                        //long fakeKeyId = 3008998260528343108L;
                        //PgpPublicKey key = pgpRing.GetPublicKey(fakeKeyId);

                        PgpPublicKey key = pgpRing.GetPublicKey(ops.KeyId);
                        
                        ops.InitVerify(key);

                        message = of.NextPgpObject();
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;                                                
                        
                        //THE OUTPUT FILENAME WILL BE BASED ON THE INPUT PARAMETER VALUE TO THIS METHOD. IF YOU WANT TO KEEP THE 
                        //ORIGINAL FILENAME, UNCOMMENT THE FOLLOWING LINE.
                        //if (!String.IsNullOrEmpty(Ld.FileName)) 
                        //    outputFile = Ld.FileName;

                        using (Stream output = File.Create(outputFile))
                        {
                            Stream dIn = Ld.GetInputStream();

                            int ch;
                            while ((ch = dIn.ReadByte()) >= 0)
                            {
                                ops.Update((byte)ch);
                                output.WriteByte((byte)ch);
                            }                            
                            output.Close();

                        }

                        PgpSignatureList p3 = (PgpSignatureList)of.NextPgpObject();
                        PgpSignature firstSig = p3[0];
                        if (ops.Verify(firstSig))
                        {
                            Console.Out.WriteLine("signature verified.");
                        }
                        else
                        {
                            Console.Out.WriteLine("signature verification failed.");
                            
                            //YOU MAY OPT TO DELETE THE OUTPUT FILE IN THE EVENT THAT VERIFICATION FAILS.
                            //FILE DELETION HAPPENS FURTHER DOWN IN THIS METHOD
                            //AN ALTERNATIVE IS TO LOG THESE VERIFICATION FAILURE MESSAGES, BUT KEEP THE OUTPUT FILE FOR FURTHER ANALYSIS
                            //deleteOutputFile = true;
                        }
                    }
                    else
                    {
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;
                        using (Stream output = File.Create(outputFile))
                        {
                            Stream unc = Ld.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                }
                else if (message is PgpLiteralData)
                {
                    PgpLiteralData ld = (PgpLiteralData)message;
                    string outFileName = ld.FileName;

                    using (Stream fOut = File.Create(outFileName))
                    {
                        Stream unc = ld.GetInputStream();
                        Streams.PipeAll(unc, fOut);
                    }
                }
                else if (message is PgpOnePassSignatureList)
                    throw new PgpException("Encrypted message contains a signed message - not literal data.");
                else
                    throw new PgpException("Message is not a simple encrypted file - type unknown.");

                #region commented code

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify()){
                        //msg = "message failed integrity check.";
                        Console.Error.WriteLine("message failed integrity check");

                        //YOU MAY OPT TO DELETE THE OUTPUT FILE IN THE EVENT THAT THE INTEGRITY PROTECTION CHECK FAILS.
                        //FILE DELETION HAPPENS FURTHER DOWN IN THIS METHOD.
                        //AN ALTERNATIVE IS TO LOG THESE VERIFICATION FAILURE MESSAGES, BUT KEEP THE OUTPUT FILE FOR FURTHER ANALYSIS
                        //deleteOutputFile = true;                        
                    }
                    else
                        //msg = "message integrity check passed.";
                        Console.Error.WriteLine("message integrity check passed");
                }
                else
                {
                    //msg = "no message integrity check.";
                    Console.Error.WriteLine("no message integrity check");
                }

                if (deleteOutputFile) File.Delete(outputFile);

                #endregion commented code
            }
            catch (PgpException ex)
            {
                throw;
            }
        }

        #endregion Decrypt

        #region Private helpers

        /*
        * A simple routine that opens a key ring file and loads the first available key suitable for encryption.
        */

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            // iterate through the key rings.
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /*
        * Search a secret key ring collection for a secret key corresponding to keyId if it exists.
        */

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        #endregion Private helpers
    }
}