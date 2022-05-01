using System;
using System.IO;
using System.Text;

namespace Dotnet.AuthentificationMode
{
    class Program
    {
        static void Main(string[] args)
        {
            var mb100 = 1000;
            var key = Salt.CreateSalt(16);
            var macKey = Salt.CreateSalt(16);
            var iv = Salt.CreateSalt(16);
            var plainText = Salt.CreateSalt(mb100);
            byte[] cipherText; 
            byte[] possibleText; 
            
            Console.WriteLine("IV : " + BitConverter.ToString(iv));
            Console.WriteLine("Key : " + BitConverter.ToString(key));
            Console.WriteLine("MAC Key : " + BitConverter.ToString(macKey));
            
            string path1 = @"/Users/olganemova/RiderProjects/Dotnet.AuthentificationMode/Dotnet.AuthentificationMode/plain.txt";
            if (!File.Exists(path1))
            {
                using (StreamWriter sw = File.CreateText(path1))
                {
                    sw.WriteLine(BitConverter.ToString(plainText));
                }	
            }

            using (AuthenticEncryptor encryptor = new AuthenticEncryptor(Mode.Encryption))
            {
                encryptor.Key = key;
                encryptor.MacKey = macKey;
                encryptor.IV = iv;
                cipherText = encryptor.ProcessData(plainText);
                
                string path2 = @"/Users/olganemova/RiderProjects/Dotnet.AuthentificationMode/Dotnet.AuthentificationMode/cipher.txt";
                if (!File.Exists(path2))
                {
                    using (StreamWriter sw = File.CreateText(path2))
                    {
                        sw.WriteLine(BitConverter.ToString(cipherText));
                    }	
                }
                //Console.WriteLine("cipher text : " + BitConverter.ToString(cipherText));
            }
            
            using (AuthenticEncryptor decryptor = new AuthenticEncryptor(Mode.Decryption))
            {
                decryptor.Key = key;
                decryptor.MacKey = macKey;
                decryptor.IV = iv;
                possibleText = decryptor.ProcessData(cipherText);
                
                string path3 = @"/Users/olganemova/RiderProjects/Dotnet.AuthentificationMode/Dotnet.AuthentificationMode/decrypted.txt";
                if (!File.Exists(path3))
                {
                    using (StreamWriter sw = File.CreateText(path3))
                    {
                        sw.WriteLine(BitConverter.ToString(possibleText));
                    }	
                }
                //Console.WriteLine("decrypted text : " + BitConverter.ToString(possibleText));
            }
        }
    }
}