using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;

namespace OpenEdigeUtils {
    internal class PgpEncryptor {

        public string Encrypt(string inputFilePath, string outputFilePath, string publicKeyPath) {
            try{

                using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
                using (Stream outputStream = File.Create(outputFilePath))
                using (Stream inputStream = File.OpenRead(inputFilePath))
                {
                    // Carregar chave pública
                    var publicKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
                    PgpPublicKey publicKey = null;

                    // Encontrar uma chave pública adequada para criptografia
                    foreach (PgpPublicKeyRing keyRing in publicKeyRingBundle.GetKeyRings())
                    {
                        foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                        {
                            if (key.IsEncryptionKey)
                            {
                                publicKey = key;
                                break;
                            }
                        }
                        if (publicKey != null)
                            break;
                    }

                    if (publicKey == null)
                    {
                        string error = "Nenhuma chave pública válida encontrada para criptografia.";
                        Console.WriteLine(error);
                        return error;
                    }

                    // Criptografar o arquivo
                    var encryptedDataGenerator = new PgpEncryptedDataGenerator(
                        SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());
                    encryptedDataGenerator.AddMethod(publicKey);

                    using (var armoredOutputStream = new ArmoredOutputStream(outputStream))
                    using (var encryptedOut = encryptedDataGenerator.Open(armoredOutputStream, new byte[1 << 16]))
                    {
                        PgpUtilities.WriteFileToLiteralData(encryptedOut, PgpLiteralData.Binary, new FileInfo(inputFilePath));
                    }

                    string successMessage = "Arquivo criptografado com sucesso!";
                    Console.WriteLine(successMessage);
                    return successMessage;
                }
            }
            catch (FileNotFoundException ex)
            {
                string error = $"Erro: Arquivo não encontrado. {ex.Message}";
                Console.WriteLine(error);
                return error;
            }
            catch (UnauthorizedAccessException ex)
            {
                string error = $"Erro: Acesso não autorizado ao arquivo. {ex.Message}";
                Console.WriteLine(error);
                return error;
            }
            catch (Exception ex)
            {
                string error = $"Erro ao criptografar arquivo com chave pública: {ex.Message}";
                Console.WriteLine(error);
                return error;
            }
        }

    }
}
