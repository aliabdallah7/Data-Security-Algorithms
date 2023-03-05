using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string ALphabets = "abcdefghijklmnopqrstuvwxyz";

        public int Letters(char letter)
        {
            int x = 0;
            while (x < 26)
            {
                while (letter == ALphabets[x])
                {
                    return x;
                }
                x++;
            }
            return -1;
        }


        public string Encrypt(string plainText, int key)
        {
            string alpha = ALphabets.ToUpper();
            string pT = plainText;
            string cT = "";

            int i = 0;
            while (i < pT.Length)
            {
                if (char.IsLetter(pT[i]))
                {
                    int fullKey = (key + Letters(pT[i]));
                    int letterIndex;
                    letterIndex = (fullKey % 26);
                    cT += alpha[letterIndex];
                }
                else
                {
                    cT += pT[i];
                }
                i++;
            }
            return cT;

        }

        public string Decrypt(string cipherText, int key)
        {
            string cT = cipherText.ToLower();
            string message = "";


            for (int y = 0; y < cT.Length; y++)
            {
                if (char.IsLetter(cT[y]))
                {
                    int fullKey = (Letters(cT[y]) - key);
                    int letterIndex;
                    letterIndex = (fullKey % 26);

                    while (letterIndex < 0)
                    {
                        letterIndex += 26;
                    }
                    message += ALphabets[letterIndex];
                }
                else
                {
                    message += cT[y];
                }
            }
            return message;
        }

        public int Analyse(string plainText, string cipherText)
        {
            string pT = plainText;
            string cT = cipherText;

            if (pT.Length != cT.Length)
            {
                return -1;
            }

            int pTIndex, cTIndex;

            char sPT = pT[0];
            char sCT = char.ToLower(cT[0]);

            pTIndex = Letters(sPT);
            cTIndex = Letters(sCT);

            int newKey = (cTIndex - pTIndex);

            if (newKey < 0)
            {
                return (newKey) + 26;
            }
            else
            {
                return (newKey) % 26;
            }
        }
    }
}