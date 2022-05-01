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
        
        public static bool IsEqual(byte[] first, byte[] second)
        {
            if (first.Length == second.Length)
            {
                for (int i = 0; i < first.Length; ++i)
                {
                    if (first[i] != second[i])
                    {
                        return false;
                    }
                }

                return true;
            }

            return false;
        }
    }
}