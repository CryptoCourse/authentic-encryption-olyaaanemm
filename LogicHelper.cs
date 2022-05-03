using System.Runtime.CompilerServices;

namespace Dotnet.AuthentificationMode
{
    public static class LogicHelper
    {
        public static byte[] Сoncatenate(byte[] first, byte[] second)
        {
            if (second == null || first == null) return first ?? second;
            
            byte[] resulted = new byte[first.Length + second.Length];
            first.CopyTo(resulted, 0);
            second.CopyTo(resulted, first.Length);
            return resulted;
        }
        
        [MethodImpl(MethodImplOptions.NoOptimization)]
        public static bool AreEqual(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= (uint)(a[i] ^ b[i]);
            return diff == 0;
        }
    }
}
