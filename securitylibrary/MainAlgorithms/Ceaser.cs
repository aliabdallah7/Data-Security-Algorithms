using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            throw new NotImplementedException();

        }

        public string Decrypt(string cipherText, int key)
        {
            throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
    }
}