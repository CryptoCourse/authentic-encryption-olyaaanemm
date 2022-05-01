using System;
using System.Security.Cryptography;

namespace Dotnet.AuthentificationMode
{
    public class AuthenticEncryptor : IDisposable // AES-CTR and HMAC-SHA-256
    {
        private const int MAC_SIZE = 32;
        private const int DATA_BLOCK_SIZE = 16;
        
        private readonly Mode _mode;
        
        private int offset;
        public byte[] IV { get; set; }
        private byte[] Mac { get; set; }
        private byte[] Buffer { get; set; }
        public  byte[] Key { get; set; }
        public byte[] MacKey { get; set; }
        private ICryptoTransform Aes128Encryptor { get; set; }
        private HMACSHA256 HMacSha256 { get; set; }
        
        public AuthenticEncryptor(Mode mode)
        {
            _mode = mode;
        }
        
        public byte[] ProcessData(byte[] data) => _mode switch
        {
            Mode.Encryption => Encrypt(data),
            Mode.Decryption => Decrypt(data),
            _ => throw new NotImplementedException($"The {_mode} mode wasn't implemented")
        };
        
        private byte[] Encrypt(byte[] data) //CTR(IV) || ED = AES(data) || MAC( CTR(IV) || ED)
        {
            InicializeEncryptor();
            
            //Console.WriteLine(BitConverter.ToString(data));
            //Console.WriteLine(BitConverter.ToString(IV));
           
            int iterations = data.Length / DATA_BLOCK_SIZE;

            for (int i = 1; i < iterations; ++i)
            {
                AddBlock(data[((i-1) * DATA_BLOCK_SIZE)..(i * DATA_BLOCK_SIZE)], false);
            }

            if (data.Length % DATA_BLOCK_SIZE != 0)
            {
                AddBlock(data[(DATA_BLOCK_SIZE * (iterations-1))..(iterations * DATA_BLOCK_SIZE)], false);
                AddBlock(data[(DATA_BLOCK_SIZE * iterations)..], true);
            }
            else
            {
                AddBlock(data[(DATA_BLOCK_SIZE * (iterations-1))..], true);
            }
            //Console.WriteLine(BitConverter.ToString(Buffer));
            Mac = HMacSha256.ComputeHash(LogicHelper.Сoncatenate(IV, Buffer));
            return LogicHelper.Сoncatenate(LogicHelper.Сoncatenate(IV, Buffer), Mac);
        }
        
        private byte[] Decrypt(byte[] data)
        {
            IV = data[..DATA_BLOCK_SIZE];
            
            InicializeDecryptor();
            
            var insideData = data[DATA_BLOCK_SIZE..(data.Length - MAC_SIZE)];
            var possibleMac = data[^MAC_SIZE..];
            
            Mac = HMacSha256.ComputeHash(LogicHelper.Сoncatenate(IV, insideData));
            
            if (!LogicHelper.IsEqual(possibleMac, Mac))
            {
                Console.WriteLine("Mac and cipher mac aren't equal! The message was transformed...");
            }
            
            //Console.WriteLine(BitConverter.ToString(insideData));
            //Console.WriteLine(BitConverter.ToString(IV));
            
            int iterations = insideData.Length / DATA_BLOCK_SIZE;

            for (int i = 1; i < iterations; ++i)
            {
                AddBlock(insideData[((i-1) * DATA_BLOCK_SIZE)..(i * DATA_BLOCK_SIZE)], false);
            }

            AddBlock(insideData[(DATA_BLOCK_SIZE * (iterations-1))..], true);
            
            //Console.WriteLine(BitConverter.ToString(possibleMac));
            //Console.WriteLine(BitConverter.ToString(Mac));
            //Console.WriteLine(BitConverter.ToString(Buffer));

            return Buffer;
        }

        private void AddBlock(byte[] dataBlock, bool isFinal)
        {
            if (isFinal)
            {
                Buffer = LogicHelper.Сoncatenate(
                    Buffer?[..offset],
                    Aes128Encryptor.TransformFinalBlock(dataBlock, 0, dataBlock.Length));
                //Console.WriteLine("1");
                //Console.WriteLine(BitConverter.ToString(IV));
                //Console.WriteLine(BitConverter.ToString(Buffer));
                //Console.WriteLine("Mac");
            }
            else
            {
                Buffer = LogicHelper.Сoncatenate(Buffer, dataBlock);
                offset += Aes128Encryptor.TransformBlock(
                    Buffer, offset, dataBlock.Length, Buffer, offset);
            }
        }

        private void InicializeEncryptor()
        {
            offset = 0; 
            
            Buffer = null;
            Mac = null;
            
            using (Aes aes128 = Aes.Create())
            {
                aes128.Key = Key;
                aes128.IV = IV;
                aes128.Padding = PaddingMode.None;
                aes128.Mode = CipherMode.CFB;
            
                Aes128Encryptor = aes128.CreateEncryptor();
            }
            
            HMacSha256 ??= new HMACSHA256();
            HMacSha256.Key = MacKey;
            HMacSha256.Initialize();
        }
        
        private void InicializeDecryptor()
        {
            offset = 0; 
            
            Buffer = null;
            Mac = null;
            
            using (Aes aes128 = Aes.Create())
            {
                aes128.Key = Key;
                aes128.IV = IV;
                aes128.Padding = PaddingMode.None;
                aes128.Mode = CipherMode.CFB;
            
                Aes128Encryptor = aes128.CreateDecryptor();
            }

            HMacSha256 ??= new HMACSHA256();
            HMacSha256.Key = MacKey;
            HMacSha256.Initialize();
        }

        public void Dispose()
        {
            HMacSha256?.Dispose();
            Aes128Encryptor?.Dispose();
        }
    }
}