using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int secretquery(int generator, int private_key, int prime)
        {
            int keyGenerate = 1;
            int xx=0;
            while (xx < private_key)
            {
                keyGenerate = (keyGenerate * generator) % prime;
                xx++;
            }
            return keyGenerate;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int firstQuery = secretquery(alpha, xa, q);
            int SecondQuery = secretquery(alpha, xb, q);

            int keyOne = 0;
            keyOne = secretquery(firstQuery, xb, q);
            int keyTwo = 0;
            keyTwo = secretquery(SecondQuery, xa, q);


            List<int> key = new List<int>();
            key.Add(keyOne);
            key.Add(keyTwo);

            return key;
        }
    }

}