using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //  throw new NotImplementedException();
            string key = null,
                emptykey = "                          ",
                alpha = "abcdefghijklmnopqrstuvwxyz",
                cipher = cipherText.ToLower();
            char[] keye = emptykey.ToCharArray(),
                text = plainText.ToCharArray();

            //delete repeated charcters from the plaintext
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int k = i + 1; k < plainText.Length; k++)
                {
                    if (text[i] == text[k])
                    {
                        text[k] = ' ';
                    }
                }
            }
            // fill char arr keye with cipher text
            string tmpText = null;
            for (int i = 0; i < text.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (text[i] == alpha[j])
                    {
                        keye[j] = cipher[i];
                        tmpText += cipher[i];
                        break;
                    }
                }

            }
            // fill remaining spaces in char arr keye with alphabetics
            for (int i = 0; i < 26; i++)
            {
                if (keye[i] == ' ')
                {
                    for (int k = 0; k < 26; k++)
                    {
                        if (!(tmpText.Contains(alpha[k])))
                        {
                            keye[i] = alpha[k];
                            tmpText += alpha[k];
                            break;
                        }
                    }
                }
            }
            // change char array to string and get the final key
            for (int i = 0; i < 26; i++)
            { key += keye[i]; }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //   throw new NotImplementedException();
            string plaintext = null,
                alpha = "abcdefghijklmnopqrstuvwxyz";
            // to make sure that all charcters are just small char
            string cipher = cipherText.ToLower();
            for (int ctr = 0; ctr < cipher.Length; ctr++)
            {   // get index of char of the cipher from the key
                for (int i = 0; i < key.Length; i++)
                {
                    if (key[i] == cipher[ctr])
                    {
                        plaintext += alpha[i];
                        break;
                    }
                }

            }

            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            //  throw new NotImplementedException();
            string cipher_text = null;
            // to make sure that all charcters are just small char
            string text = plainText.ToUpper();
            for (int ctr = 0; ctr < text.Length; ctr++)
            {
                cipher_text += key[(((int)text[ctr] - 65))];
            }

            return cipher_text.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            // throw new NotImplementedException();
            string plaintext = null;
            char[] freq_alpha = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };
            char[] ciphertext = cipher.ToLower().ToCharArray();
            int[] freq_cipher = new int[26];
            int[] freq_cipher_2 = new int[26];
            // get frequency of chars in the cipher text
            for (int charcter = 'a'; charcter <= 'z'; charcter++)
            {
                int frequency_ctr = 0;
                for (int k = 0; k < ciphertext.Length; k++)
                {
                    if (charcter == ciphertext[k])
                    { frequency_ctr++; }
                }
                freq_cipher[((int)charcter - 97)] = frequency_ctr;
                freq_cipher_2[((int)charcter - 97)] = frequency_ctr;
            }

            string text = null;
            // sort the fequency array by higher order
            Array.Sort(freq_cipher_2);
            Array.Reverse(freq_cipher_2);
            //get the sorted charcters with high frequency
            for (int i = 0; i < 26; i++)
            {
                for (int k = 0; k < 26; k++)
                {
                    if ((freq_cipher_2[i] == freq_cipher[k]))
                    {
                        text += (char)(k + 97);
                        break;
                    }
                }
            }
            // mapping the charcters and get the plaintext
            for (int i = 0; i < ciphertext.Length; i++)
            {
                for (int k = 0; k < 26; k++)
                {
                    if (ciphertext[i] == text[k])
                    {
                        ciphertext[i] = freq_alpha[k];
                        break;
                    }
                }
            }
            // change char array to string and get the final plaintext
            for (int i = 0; i < ciphertext.Length; i++)
            {
                plaintext += ciphertext[i];
            }
            return plaintext;
        }
    }
}