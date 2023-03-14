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
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            // Convert the ciphertext and key to lowercase to handle plaintext and ciphertext that contain both uppercase and lowercase letters
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            //indk-> index of the keyS char 
            //indp_> index of the cipherS char
            int indk, indp;
            // Initialize variables for the plaintext and the index of the current character in the key
            string plainText = "";


            // Iterate over each character in the ciphertext to decrypt it using the key
            for (int i = 0; i < cipherText.Length; i++)
            {
                indk = alpha.IndexOf(key[i]);
                //get the row that is start with the key char to know the distance with PTcahr
                string temp="";
                for(int d = 0; d< 26; d++)
                {
                    temp =temp+alpha[(indk+d)%26];
                }
                indp = temp.IndexOf(plainText[i]);
                // get the index of the column thats has the pt char
                int indC = indp - indk;

                // get the char 
                plainText += alpha[indC];
             
           
            }
         
            return plainText;

            
        }

        public string Encrypt(string plainText, string key)
        {
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            // Convert the plaintext and key to lowercase to handle plaintext and ciphertext that contain both uppercase and lowercase letters
            plainText = plainText.ToLower();
            // Initialize an empty string to store the ciphertext and an index to keep track of the current character in the key
            string cipherText = "";
           
            int indk, indp;
            // Loop through each character in the plaintext to encrypt it using the key
            for (int i = 0; i < plainText.Length; i++)
            {
                indk = alpha.IndexOf(key[i]);
                indp = alpha.IndexOf(plainText[i]);
                // index of the char in the key and add the number of steps to the PTcolumn 
                int encryptedChar = (indk + indp ) % 26 ;

                // Add the encrypted character to the ciphertext string
                cipherText += alpha[encryptedChar];
               
            }

            // Return the encrypted ciphertext
            return cipherText;
         
        }
    }
}
