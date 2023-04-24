namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {

            int a1 = 1, result, a2 = 0, a3 = baseN, q, b1 = 0, b2 = 1, b3 = number, temp1, temp = baseN, temp2, temp3;

            while (b3 != 0 && b3 != 1)

            {
                temp1 = b1;
                temp2 = b2;
                temp3 = b3;
                q = a3 / b3;
                b3 = a3 % temp3;
                a3 = temp3;
                b1 = a1 - b1 * q;
                b2 = a2 - b2 * q;
                a1 = temp1;
                a2 = temp2;

            }

            if (b3 == 0)
                return -1;

            if (b3 == 1)
            {
                result = (b2 + temp) % temp;
                return result;
            }

            return -1;

        }
    }
}
