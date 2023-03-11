using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {

            throw new NotImplementedException();

        }


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            string plainText = "";
            int j = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int c = (cipherText[i] - key[j] + 26) % 26 + 'a';
                plainText += (char)c;
                key += plainText[j];
                j++;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();

            string cipherText = "";
            int j = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                int c = (plainText[i] + key[j] - 2 * 'a') % 26 + 'a';
                cipherText += (char)c;
                key += plainText[i];
                j++;
            }
            return cipherText;
        }
    }
}
