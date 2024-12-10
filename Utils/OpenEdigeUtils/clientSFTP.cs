using System;
using System.IO;
using Renci.SshNet;

namespace OpenEdigeUtils {
    public class SFTPClient {
        private string host;
        private string username;
        private string privateKeyPath;
        private string passphrase;

        public SFTPClient(string host, string username, string privateKeyPath, string passphrase) {
            this.host = host;
            this.username = username;
            this.privateKeyPath = privateKeyPath;
            this.passphrase = passphrase;
        }

        private SftpClient GetSftpClient() {
            var privateKey = new PrivateKeyFile(privateKeyPath, passphrase);
            var client = new SftpClient(host, username, privateKey);
            return client;
        }

        public string List(string remoteDirectory) {
            try
            {
                using (var client = GetSftpClient())
                {
                    client.Connect();
                    var files = client.ListDirectory(remoteDirectory);
                    string fileNames = string.Empty;

                    foreach (var file in files)
                    {
                        // Ignorar diretórios "." e ".."
                        if (!file.Name.StartsWith("."))
                        {
                            // Concatena os nomes dos arquivos com ";"
                            fileNames += file.Name + ";";
                        }
                    }

                    client.Disconnect();

                    // Retorna a string sem o último ";"
                    return string.IsNullOrEmpty(fileNames) ? fileNames : fileNames.TrimEnd(';');
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao listar arquivos: {ex.Message}");
                return $"Erro: {ex.Message}";
            }
        }

        // Enviar um arquivo para o servidor SFTP
        public bool Upload(string localFilePath, string remoteFilePath) {
            try
            {
                using (var client = GetSftpClient())
                {
                    client.Connect();
                    using (var fileStream = new FileStream(localFilePath, FileMode.Open))
                    {
                        client.UploadFile(fileStream, remoteFilePath);
                    }
                    client.Disconnect();
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao enviar arquivo: {ex.Message}");
                return false;
            }
        }

        // Baixar um arquivo do servidor SFTP
        public bool Download(string remoteFilePath, string localFilePath) {
            try
            {
                using (var client = GetSftpClient())
                {
                    client.Connect();
                    using (var fileStream = new FileStream(localFilePath, FileMode.Create))
                    {
                        client.DownloadFile(remoteFilePath, fileStream);
                    }
                    client.Disconnect();
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao baixar arquivo: {ex.Message}");
                return false;
            }
        }
    }
}