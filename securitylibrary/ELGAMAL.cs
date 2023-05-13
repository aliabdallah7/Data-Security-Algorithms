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
            // applying the mathematical equation 
            return (c2 * ModInverse(ModPow(c1, x, q), q)) % q;
        }

        ///<summary>
        /// Calculates the modular exponentiation x1^x2 mod mod
        ///</summary>
        ///<param name="x1">The base</param>
        ///<param name="x2">The exponent</param>
        ///<param name="mod">The modulus</param>
        ///<returns>The result of the modular exponentiation</returns>
        private int ModPow(int x1, int x2, int mod)
        {
            // Initialize result variable with 1
            int res = 1;

            // While loop to calculate exponentiation
            while (x2 > 0)
            {
                // Check if the current power of 2 is set in the exponent
                if ((x2 & 1) == 1)
                {
                    // Multiply current result by x1 and take the modulus with respect to mod

                    res = (res * x1) % mod;
                }
                // Calculate x1^2 % mod to use in the next iteration of the while loop
                x1 = (x1 * x1) % mod;


                // Shift the bits of x2 to the right by 1 to divide by 2
                x2 = x2 >> 1;
            }
            return res;
        }

        ///<summary>
        /// Calculates the modular multiplicative inverse of a modulo n using the extended Euclidean algorithm
        ///</summary>
        ///<param name="a">The integer for which to find the inverse</param>
        ///<param name="n">The modulus</param>
        ///<returns>The modular multiplicative inverse of a modulo n</returns>
        private int ModInverse(int x, int mod)
        {
            // Initialize four variables temporary, newTemporary, remainder and newRemainder to be used in the extended Euclidean algorithm

            int temporary = 0, newTemporary = 1, remainder = mod, newRemainder = x;


            // Extended Euclidean algorithm to calculate the modular multiplicative inverse
            while (newRemainder != 0)
            {
                // Calculate the quotient of remainder and newRemainder
                int quotient = remainder / newRemainder;

                // Store newTemporary in x temporary variable
                int tempT = newTemporary;

                // Calculate the new value of newTemporary
                newTemporary = temporary - quotient * newTemporary;

                // Set temporary to the old value of newTemporary
                temporary = tempT;

                // Store newRemainder in x temporary variable
                int tempR = newRemainder;

                // Calculate the new value of newRemainder
                newRemainder = remainder - quotient * newRemainder;

                // Set remainder to the old value of newRemainder
                remainder = tempR;
            }

            // If temporary is negative, add mod to temporary
            if (!(temporary >= 0))
            {
                temporary += mod;
            }

            return temporary;
        }
    }
}
