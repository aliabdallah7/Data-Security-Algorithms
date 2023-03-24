using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        
        public string Decrypt(string cipherText, List<int> key)
        {
            int numRows = (int)Math.Ceiling((double)cipherText.Length / key.Count);
            char[,] grid = new char[numRows, key.Count];

            int charIndex = 0;

      
            for (int col = 0; col < key.Count; col++)
            {
                
                int colIndex = key.IndexOf(col+1) ;
                for (int row = 0; row < numRows; row++)
                {
                    if (charIndex < cipherText.Length)
                    {
                        grid[row, colIndex] = cipherText[charIndex];
                    }
                    else
                    {
                        grid[row, colIndex] = 'X';
                    }
                    charIndex++;
                }
            }

            string plainText = "";
            for (int row = 0; row < numRows; row++)
            {
                for (int col = 0; col < key.Count; col++)
                {
                    
                        plainText += grid[row, col];
                    
                }
            }

            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int numCols = key.Count;
            int numRows = (int)Math.Ceiling((double)plainText.Length / numCols);

            int numEmptyCells = numRows * numCols - plainText.Length;
            if (numEmptyCells > 0)
            {
                plainText = plainText.PadRight(plainText.Length + numEmptyCells, 'x');
            }

            char[,] matrix = new char[numRows, numCols];
            int index = 0;
            for (int row = 0; row < numRows; row++)
            {
                for (int col = 0; col < numCols; col++)
                {
                    matrix[row, col] = plainText[index];
                    index++;
                }
            }

            string cipherText = "";
            int[] keyArray = key.ToArray();
            
                for (int col = 0; col < numCols; col++)
                {
                    int colIndex = key.IndexOf(col+1);
                    
                    for (int row = 0; row < numRows; row++)
                    {
                    cipherText += matrix[row, colIndex];
                    }
                
                }

            return cipherText;


        }
    }
}
