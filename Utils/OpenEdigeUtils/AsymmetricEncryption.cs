using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Org.BouncyCastle.Bcpg;


namespace OpenEdigeUtils {
    public class AsymmetricEncryption {

        private PgpDecryptor pgpDecryptor;
        private PgpEncryptor pgpEncryptor;

        public void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyFilePath, string privateKeyPassword) {
            try
            {
                Console.WriteLine("Iniciando a descriptografia...");

                pgpDecryptor = new PgpDecryptor();

                // Chama o método de descriptografia da classe PgpDecryptor.
                pgpDecryptor.DecryptFile( inputFilePath, outputFilePath, privateKeyFilePath, privateKeyPassword);

                Console.WriteLine($"Arquivo descriptografado com sucesso em: {outputFilePath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro durante a descriptografia: {ex.Message}");
            }

        }


        public void EncryptFile(string filePath, string outputFilePath, string publicKeyFilePath){

            pgpEncryptor = new PgpEncryptor();

            pgpEncryptor.Encrypt(filePath, outputFilePath, publicKeyFilePath);

            Console.WriteLine($"Arquivo criptografado com sucesso em: {outputFilePath}");

        }
    }  
}
