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
            string key=cipherText;
            cipherText = cipherText.ToLower();
            

            int z = plainText.Length - cipherText.Length;
            for (int i = 0; i < z; i++)
            {
                int c = i % cipherText.Length;
                key = key+ cipherText[c];
            }
            return key;
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            // Convert the ciphertext and key to lowercase to handle plaintext and ciphertext that contain both uppercase and lowercase letters
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            // Initialize variables for the plaintext and the index of the current character in the key
            string plainText = "";
            int j = 0;

            // Iterate over each character in the ciphertext to decrypt it using the key
            for (int i = 0; i < cipherText.Length; i++)
            {
                // Calculate the ASCII value of the decrypted character using the ASCII values of the corresponding characters in the ciphertext and the key
                int c = (cipherText[i] - key[j] + 26) % 26 + 'a';

                // Add the decrypted character to the plaintext
                plainText += (char)c;

                // Add the current plaintext character to the key for use in decrypting the next ciphertext character
                key += plainText[j];

                // Increment the index of the current character in the key
                j++;
            }

            // Return the decrypted plaintext
            return plainText;

            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            // Convert the plaintext and key to lowercase to handle plaintext and ciphertext that contain both uppercase and lowercase letters
            plainText = plainText.ToLower();
            key = key.ToLower();

            // Initialize an empty string to store the ciphertext and an index to keep track of the current character in the key
            string cipherText = "";
            int keyIndex = 0;

            // Loop through each character in the plaintext to encrypt it using the key
            for (int i = 0; i < plainText.Length; i++)
            {
                // Calculate the ASCII value of the encrypted character by adding the ASCII values of the corresponding plaintext and key characters
                // Subtract 2 times the ASCII value of 'a' to shift the range of the resulting values to be between 0 and 25
                // Take the result modulo 26 to wrap the value around to the beginning of the alphabet if necessary
                // Add the ASCII value of 'a' to shift the range back to the ASCII values for lowercase letters
                int encryptedChar = (plainText[i] + key[keyIndex] - 2 * 'a') % 26 + 'a';

                // Add the encrypted character to the ciphertext string
                cipherText += (char)encryptedChar;

                // Add the current plaintext character to the key for use in encrypting the next plaintext character
                key += plainText[i];

                // Increment the key index to point to the next character in the key
                keyIndex++;
            }

            // Return the encrypted ciphertext
            return cipherText;
            throw new NotImplementedException();
        }
    }
}
