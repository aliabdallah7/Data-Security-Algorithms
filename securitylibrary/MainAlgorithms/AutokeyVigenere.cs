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
            // Convert the ciphertext to lowercase to handle plaintext and ciphertext that contain both uppercase and lowercase letters
            cipherText = cipherText.ToLower();

            // Initialize variables for the key and the index of the current character in the key
            string key = "";
            int keyIndex = 0;

            // Iterate over each character in the plaintext to recover the key
            for (int i = 0; i < plainText.Length; i++)
            {
                // Calculate the difference between the ASCII values of the corresponding characters in the plaintext and ciphertext to recover the key character
                int x = (cipherText[i] - plainText[i] + 26) % 26;
                x += 'A';
                char keyChar = (char)(x);

                // Add the key character to the key if the key is not yet as long as the plaintext
                if (keyIndex < plainText.Length)
                {
                    key += keyChar;
                    keyIndex++;
                }
            }

            // Initialize a temporary key with the first character of the recovered key
            string temp = "";
            temp = temp + key[0];

            // Iterate over the remaining characters in the recovered key to try to guess the full key
            int klength = key.Length;
            for (int i = 1; i < klength; i++)
            {
                // If the encrypted plaintext matches the actual ciphertext with the current key, return the current key
                if (cipherText.Equals(Encrypt(plainText, temp)))
                {
                    return temp;
                }

                // Add the next character of the recovered key to the temporary key
                temp = temp + key[i];
            }

            // Return the recovered key if it could not be guessed more precisely
            return key;
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
        }
    }
}
