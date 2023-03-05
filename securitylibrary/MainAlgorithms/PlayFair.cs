using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        // Helper function to generate the Playfair matrix
        private char[,] GeneratePlayfairMatrix(string key)
        {
            // Remove spaces and duplicate letters from the key
            key = key.Replace(" ", "").ToLower();
            key = new string(key.Distinct().ToArray());

            // Initialize the matrix with the key
            char[,] matrix = new char[5, 5];
            int i = 0, j = 0;
            foreach (char c in key)
            {
                matrix[i, j] = c;
                j++;
                if (j == 5)
                {
                    i++;
                    j = 0;
                }
            }

            // Fill the rest of the matrix with the remaining letters
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            foreach (char c in alphabet)
            {
                if (!key.Contains(c))
                {
                    matrix[i, j] = c;
                    j++;
                    if (j == 5)
                    {
                        i++;
                        j = 0;
                    }
                }
            }

            return matrix;
        }


        public string Decrypt(string cipherText, string key)
        {
            // Generate the playfair matrix
            char[,] matrix = GeneratePlayfairMatrix(key);

            // Remove any non-alphabetic characters and convert to lowercase
            cipherText = new string(cipherText.Where(char.IsLetter).ToArray()).ToLower();

            // Replace any 'j' characters with 'i'
            cipherText = cipherText.Replace("j", "i");

            // If the length of the plaintext is odd, add an 'x' character to the end
            if (cipherText.Length % 2 == 1)
            {
                cipherText += "x";
            }

            // Decrypt the cipher text by pairs of letters
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char c1 = cipherText[i];
                char c2 = cipherText[i + 1];
                int r1 = 0, c1Index = 0, r2 = 0, c2Index = 0;

                // Find the row and column indices of the two characters
                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (matrix[row, col] == c1)
                        {
                            r1 = row;
                            c1Index = col;
                        }
                        if (matrix[row, col] == c2)
                        {
                            r2 = row;
                            c2Index = col;
                        }
                    }
                }

                // Handle the cases where the two characters are in the same row, column or neither
                if (r1 == r2)
                {
                    plainText += matrix[r1, (c1Index + 4) % 5];
                    plainText += matrix[r2, (c2Index + 4) % 5];
                }
                else if (c1Index == c2Index)
                {
                    plainText += matrix[(r1 + 4) % 5, c1Index];
                    plainText += matrix[(r2 + 4) % 5, c2Index];
                }
                else
                {
                    plainText += matrix[r1, c2Index];
                    plainText += matrix[r2, c1Index];
                }
            }

            // Remove any 'x' characters that were inserted between identical letters in the plaintext
            string PT = plainText;
            if (plainText[plainText.Length - 1] == 'x')
            {
                PT = PT.Remove(plainText.Length - 1);
            }

            int k = 0;
            for (int i = 0; i < PT.Length; i++)
            {
                if (plainText[i] == 'x')
                {
                    if (plainText[i - 1] == plainText[i + 1])
                    {
                        if (i + k < PT.Length && (i - 1) % 2 == 0)
                        {
                            PT = PT.Remove(i + k, 1);
                            k--;
                        }
                    }
                }
            }
            string fullPlainText = "";
            fullPlainText += PT;

            return fullPlainText;
        }


        public string Encrypt(string plainText, string key)
        {
            // Generate the Playfair matrix
            char[,] matrix = GeneratePlayfairMatrix(key);

            // Remove spaces and non-alphabetic characters from the plaintext
            plainText = new string(plainText.Where(char.IsLetter).ToArray()).ToLower();


            // Replace any pair of identical letters with 'x'
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }


            // Pad the plaintext with 'x' if necessary
            if (plainText.Length % 2 == 1)
            {
                plainText += "x";
            }

            // Encrypt the plaintext
            string cipherText = "";
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                char c1 = plainText[i];
                char c2 = plainText[i + 1];
                int r1 = 0, c1Index = 0, r2 = 0, c2Index = 0;

                // Find the row and column indices of the two characters
                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (matrix[row, col] == c1)
                        {
                            r1 = row;
                            c1Index = col;
                        }
                        if (matrix[row, col] == c2)
                        {
                            r2 = row;
                            c2Index = col;
                        }
                    }
                }

                // Handle the cases where the two characters are in the same row, column or neither
                if (r1 == r2)
                {
                    cipherText += matrix[r1, (c1Index + 1) % 5];
                    cipherText += matrix[r2, (c2Index + 1) % 5];
                }
                else if (c1Index == c2Index)
                {
                    cipherText += matrix[(r1 + 1) % 5, c1Index];
                    cipherText += matrix[(r2 + 1) % 5, c2Index];
                }
                else
                {
                    cipherText += matrix[r1, c2Index];
                    cipherText += matrix[r2, c1Index];
                }
            }

            Console.WriteLine(cipherText.ToUpper(), "\n\n");
            return cipherText.ToUpper();

        }
    }
}