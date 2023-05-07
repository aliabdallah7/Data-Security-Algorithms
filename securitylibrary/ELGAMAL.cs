using System;
using System.Collections.Generic;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            // Compute C1 = alpha^k mod q
            long c1 = ModExp(alpha, k, q);

            // Compute C2 = m * y^k mod q
            long c2 = (m * ModExp(y, k, q)) % q;

            return new List<long> { c1, c2 };
        }


        // Computes the modular exponentiation a^b mod n using the binary method
        private long ModExp(long a, long b, long n)
        {
            long res = 1;
            a %= n;

            while (b > 0)
            {
                if ((b & 1) == 1)
                {
                    res = (res * a) % n;
                }

                b >>= 1;
                a = (a * a) % n;
            }

            return res;
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            throw new NotImplementedException();

        }
    }
}
