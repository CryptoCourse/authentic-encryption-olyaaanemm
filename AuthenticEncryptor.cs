using System;
using System.Security.Cryptography;

namespace Dotnet.AuthentificationMode
{
    public class AuthenticEncryptor : IDisposable   // AES-CTR and HMAC-SHA-256
    {
        private byte[] Buffer { get; set; }
        private byte[] Mac { get; set; }
        private ICryptoTransform Aes128Encryptor { get; set; }
        private HMACSHA256 HMacSha256 { get; set; }
        
        private readonly Mode _mode;
        
        private const int MAC_SIZE = 32;
        private const int DATA_BLOCK_SIZE = 16;

        private int _offset;

        public byte[] IV { get; set; }
        public  byte[] Key { get; set; }
        public byte[] MacKey { get; set; }
        
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
        
        private byte[] Encrypt(byte[] data)
        {
            Initialize();
            
            int iterations = data.Length / DATA_BLOCK_SIZE;

            for (int i = 1; i <= iterations; ++i)
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

            return LogicHelper.–°oncatenate(LogicHelper.–°oncatenate(IV, Buffer), HMacSha256.Hash);
        }
        
        private byte[] Decrypt(byte[] data)
        {
            if (data.Length < DATA_BLOCK_SIZE)
            {
                throw new ArgumentException("invalid data size");
            }
            
            IV = data?[..DATA_BLOCK_SIZE];
            
            Initialize();
            
            var insideData = data[DATA_BLOCK_SIZE..(data.Length - MAC_SIZE)];
            var possibleMac = data[^MAC_SIZE..];

            int iterations = insideData.Length / DATA_BLOCK_SIZE;

            for (int i = 1; i < iterations; ++i)
            {
                AddBlock(insideData[((i-1) * DATA_BLOCK_SIZE)..(i * DATA_BLOCK_SIZE)], false);
            }

            AddBlock(insideData[(DATA_BLOCK_SIZE * (iterations-1))..], true);

            if (!LogicHelper.AreEqual(possibleMac,  HMacSha256.Hash))
            {
                Console.WriteLine("Mac and cipher mac aren't equal! The message was transformed...");
            }
            
            return Buffer;
        }

        private void AddBlock(byte[] dataBlock, bool isFinal)
        {
            if (isFinal)
            {
                switch (_mode)
                {
                    case Mode.Decryption:
                        HMacSha256.TransformFinalBlock(dataBlock, 0, dataBlock.Length);
                        Mac = HMacSha256.Hash;
                        dataBlock = Aes128Encryptor.TransformFinalBlock(dataBlock, 0, dataBlock.Length);
                        break;
                    case Mode.Encryption: 
                        dataBlock = Aes128Encryptor.TransformFinalBlock(dataBlock, 0, dataBlock.Length);
                        HMacSha256.TransformFinalBlock(dataBlock,0,  dataBlock.Length);
                        Mac = HMacSha256.Hash;
                        break;
                    default:
                        throw new NotImplementedException("This mode wasn't implemented yet!");
                }
            }
            else
            {
                switch (_mode)
                {
                    case Mode.Decryption: 
                        _offset += HMacSha256.TransformBlock(
                            dataBlock, 0, dataBlock.Length, Mac, _offset);
                        Aes128Encryptor.TransformBlock(
                            dataBlock, 0, dataBlock.Length, dataBlock, 0);
                        break;
                    case Mode.Encryption: 
                        Aes128Encryptor.TransformBlock(
                            dataBlock, 0, dataBlock.Length, dataBlock, 0);
                        _offset += HMacSha256.TransformBlock(
                            dataBlock, 0, dataBlock.Length, Mac, _offset);
                        break;
                    default:
                        throw new NotImplementedException("This mode wasn't implemented yet!");
                }
            }
            Buffer = LogicHelper.–°oncatenate(Buffer, dataBlock);
        }
        private void Initialize()
        {
            _offset = 0; 
            
            Buffer = null;
            Mac = null;
            
            using (Aes aes128 = Aes.Create())
            {
                aes128.Key = Key;
                aes128.Padding = PaddingMode.None;
                aes128.Mode = CipherMode.CFB;

                switch (_mode)
                {
                    case Mode.Decryption:
                        aes128.IV = IV ?? throw new ArgumentException("Empty IV for decryption!");
                        Aes128Encryptor = aes128.CreateDecryptor();
                        break;
                    case Mode.Encryption:
                        aes128.IV = IV ??= Salt.CreateSalt(DATA_BLOCK_SIZE);
                        Aes128Encryptor = aes128.CreateEncryptor();
                        break;
                    default:
                        throw new NotImplementedException("The mode wasn't implemented yest!");
                }
            }

            HMacSha256 ??= new HMACSHA256();
            HMacSha256.Key = MacKey ??= Salt.CreateSalt(DATA_BLOCK_SIZE);
            HMacSha256.Initialize();
            _offset += HMacSha256.TransformBlock(
                IV, 0, IV.Length, Mac, _offset);
        }

        public void Dispose()
        {
            HMacSha256?.Dispose();
            Aes128Encryptor?.Dispose();
        }
    }
}
