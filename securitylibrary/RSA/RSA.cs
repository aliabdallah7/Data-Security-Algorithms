using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int GetPower(int num1, int num2, int num3)
        {
            int res = 1;
            int i = 0;
            while (i < num2)
            {
                res = (res * num1) % num3;
                i++;
            }
            return res;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int C = GetPower(M, e, n);
            return C;
        }
        public AES.ExtendedEuclid ExtendedEuclidObj = new AES.ExtendedEuclid();
        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            e = ExtendedEuclidObj.GetMultiplicativeInverse(e, (p-1)*(q-1));
            int M = GetPower(C, e, n);
            return M;
        }
    }
}
