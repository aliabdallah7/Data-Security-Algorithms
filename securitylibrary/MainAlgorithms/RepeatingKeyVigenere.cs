using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToLower();
            int z = plainText.Length - cipherText.Length;
            if (z>0)
            {
                key = cipherText;
                for (int i = 0; i < z; i++)
                {
                    int c = i % cipherText.Length;
                    key = key + cipherText[c];
                }
            }
            else if(z<0)
            {
                key = cipherText.Substring(0, cipherText.Length + z);

            }
            else
            {
                key = cipherText;
            }
  
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // Define the alphabet used for encryption
            string alpha = "abcdefghijklmnopqrstuvwxyz";

            // Convert the ciphertext and key to lowercase to handle plaintext and ciphertext that contain both uppercase and lowercase letters
            cipherText = cipherText.ToLower();

            int temp0 = 0;

            // If the key length is not equal to the ciphertext length, repeat the key until it matches the length of the ciphertext
            while (key.Length != cipherText.Length)
            {
                key = key + key[temp0];
                temp0++;
            }

            //indk-> index of the keyS char 
            //indp_-> index of the cipherS char
            int indk, indp_;

            // Initialize an empty string to store the plaintext
            string plainText = "";

            // Iterate over each character in the ciphertext to decrypt it using the key
            for (int i = 0; i < cipherText.Length; i++)
            {
                // Get the index of the current character in the key and the ciphertext
                indk = alpha.IndexOf(key[i]);
                indp_ = alpha.IndexOf(cipherText[i]);

                // Calculate the index of the decrypted character by subtracting the index of the key character from the index of the ciphertext character, then adding 26 and taking the modulus of 26 to wrap around to the end of the alphabet if necessary
                int plainChar = (indp_ - indk + 26) % 26;

                // Add the decrypted character to the plaintext string
                plainText += alpha[plainChar];
            }

            // Return the decrypted plaintext
            return plainText;
        }


        public string Encrypt(string plainText, string key)
        {
            // Define the alphabet used for encryption
            string alpha = "abcdefghijklmnopqrstuvwxyz";

            // Convert the plaintext and key to lowercase to handle plaintext and ciphertext that contain both uppercase and lowercase letters
            plainText = plainText.ToLower();

            // Initialize an empty string to store the ciphertext
            string cipherText = "";
            int temp = 0;

            // If the key length is not equal to the plaintext length, repeat the key until it matches the length of the plaintext
            while (key.Length != plainText.Length)
            {
                key = key + key[temp];
                temp++;
            }

            //indk-> index of the keyS char 
            //indp-> index of the plainS char
            int indk, indp;

            // Loop through each character in the plaintext to encrypt it using the key
            for (int i = 0; i < plainText.Length; i++)
            {
                // Get the index of the current character in the key and the plaintext
                indk = alpha.IndexOf(key[i]);
                indp = alpha.IndexOf(plainText[i]);

                // Calculate the index of the encrypted character by adding the indexes of the key and plaintext characters, then taking the modulus of 26 to wrap around to the beginning of the alphabet if necessary
                int encryptedChar = (indk + indp) % 26;

                // Add the encrypted character to the ciphertext string
                cipherText += alpha[encryptedChar];
            }

            // Return the encrypted ciphertext
            return cipherText;
        }

    }
}
