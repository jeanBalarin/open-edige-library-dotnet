using Org.BouncyCastle.Bcpg.OpenPgp;
//using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;


namespace OpenEdigeUtils {
    internal class PgpDecryptor {

        public PgpDecryptor(){}

        public void DecryptFile( string inputFilePath, string outputFilePath, string privateKeyFilePath, string privateKeyPassword) {
        /*******************************************************************************************************************************
         * Realiza o tratamento necessário para chaves PGP, cujo o uso na versão 4.8 não é suportado.
         *******************************************************************************************************************************/
            try{

                // Carregar chave privada
                PgpPrivateKey privateKey = LoadPrivateKey(privateKeyFilePath, privateKeyPassword);

                // Abrir o arquivo PGP
                using (Stream inputStream = File.OpenRead(inputFilePath))
                using (Stream outputStream = File.Create(outputFilePath)){

                    PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                    PgpObject pgpObject = pgpObjectFactory.NextPgpObject();

                    // Processar mensagens criptografadas
                    if (pgpObject is PgpEncryptedDataList encryptedDataList){

                        PgpEncryptedData encryptedData = encryptedDataList[0];

                        if (encryptedData is PgpPublicKeyEncryptedData publicKeyEncryptedData){

                            using (Stream clearDataStream = publicKeyEncryptedData.GetDataStream(privateKey)){

                                PgpObjectFactory clearFactory = new PgpObjectFactory(clearDataStream);
                                PgpObject message = clearFactory.NextPgpObject();

                                // Lidar com mensagens literais (o conteúdo do arquivo)
                                if (message is PgpLiteralData literalData){

                                    Stream literalStream = literalData.GetInputStream();
                                    Streams.PipeAll(literalStream, outputStream);
                                    Console.WriteLine("Arquivo descriptografado com sucesso!");

                                } else{

                                    throw new InvalidOperationException("Formato inesperado dentro do arquivo PGP.");

                                }

                            }
                        } else {

                            throw new InvalidOperationException("Nenhuma mensagem criptografada foi encontrada.");

                        }
                    } else {

                        throw new InvalidOperationException("Arquivo PGP inválido ou corrompido.");

                    }
                }
            }
            catch (Exception ex){

                Console.WriteLine("Erro ao descriptografar arquivo PGP: " + ex.Message);

            }

        }

        private PgpPrivateKey LoadPrivateKey(string keyFilePath, string password) {
        /*****************************************************************************
         *   Carrega o arquivo da chave privada e realiza os tratamentos necessários
         *   para importar a chave e ela possa ser usada 
         *****************************************************************************/
            using (Stream keyIn = File.OpenRead(keyFilePath)){

                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings()){

                    foreach (PgpSecretKey secretKey in keyRing.GetSecretKeys()){

                        if (secretKey.IsSigningKey){

                            PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(password.ToCharArray());
                                                                //ExtractPrivateKey(password.ToCharArray(), new SecureRandom()); GPT Solution
                            if (privateKey != null){

                                return privateKey;

                            }
                                
                        }
                    }
                }
            }

            throw new ArgumentException("Chave privada não encontrada ou senha incorreta.");
        }

    }
}
