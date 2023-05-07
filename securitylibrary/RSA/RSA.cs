using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        //Function to get (number1 power of number2) mod number3
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
            // Get (M power(e)) mod n .
            int C = GetPower(M, e, n);
            return C;
        }
        public AES.ExtendedEuclid ExtendedEuclidObj = new AES.ExtendedEuclid();
        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            // Get Multiplicative Inverse of e mod n where n is equal to (p-1)*(q-1) as p , q are prime numbers.
            e = ExtendedEuclidObj.GetMultiplicativeInverse(e, (p-1)*(q-1));
            // Get c power(e) mod n .
            int M = GetPower(C, e, n);
            return M;
        }
    }
}
