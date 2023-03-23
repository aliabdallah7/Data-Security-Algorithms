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
            // Convert the ciphertext to lowercase to handle plaintext and ciphertext that contain both uppercase and lowercase letters
            cipherText = cipherText.ToLower();

            // Initialize variables for the key and the alphabet string
            string key = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            //indc -> index of the cipherS char 
            //indp_ -> index of the plainS char
            int indc, indp_;

            // Iterate over each character in the cipherText to recover the key
            for (int i = 0; i < cipherText.Length; i++)
            {
                // Get the index of the current character in the plaintext and the ciphertext
                indc = alphabet.IndexOf(cipherText[i]);
                indp_ = alphabet.IndexOf(plainText[i]);

                // Calculate the index of the decrypted character by subtracting the index of the plainText character from the index of the ciphertext character, then adding 26 and taking the modulus of 26 to wrap around to the end of the alphabet if necessary
                int keyChar = (indc - indp_ + 26) % 26;

                // Add the decrypted character to the key string
                key += alphabet[keyChar];
            }

            // Initialize a temporary key with the first character of the recovered key
            string temp_key = "";
            temp_key = temp_key +key[0];

            // Iterate over the remaining characters in the recovered key to try to guess the full key
            for (int i = 1; i < key.Length; i++)
            {
                // If the encrypted plaintext matches the actual ciphertext with the current key, return the current key
                if (cipherText.Equals(Encrypt(plainText, temp_key)))
                    return temp_key;

                // Add the next character of the recovered key to the temporary key
                temp_key = temp_key + key[i];
            }

            // Return the recovered key if it could not be guessed more precisely
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
