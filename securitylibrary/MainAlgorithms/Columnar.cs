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

           
            //convert every text to lowerCase
            cipherText = cipherText.ToLower();

            plainText = plainText.ToLower();


            //the key list
            List<int> key = new List<int>();


            //key dictionary
            Dictionary<int, int> keyDic = new Dictionary<int, int>();



            //main dictionary 

            //make a dictionary 
            SortedDictionary<int, int> mainDic = new SortedDictionary<int, int>();


            int keySize = 2;
            bool keyFound = false;
            do
            {
                //set columns and rows 


                int numCols = keySize;


                int numRows = (int)Math.Ceiling((double)plainText.Length / keySize);

                int charIndex = 0;


                string[,] matrix = new string[numRows, numCols];
                for (int row = 0; row < numRows; row++)
                {
                    for (int col = 0; col < numCols; col++)
                    {
                        if (charIndex < plainText.Length)
                        {
                            matrix[row, col] = plainText[charIndex].ToString();
                            charIndex++;
                        }
                        else
                        {

                            matrix[row, col] = "";

                        }
                    }
                }


                //<summary>
                //cipherChunks is a chunk represents a column
                //
                //</summary>
                List<string> cipherChunks = new List<string>();
                //dividing the cipher into columns

                for (int col = 0; col < keySize; col++)
                {
                    string chunk = "";
                    for (int row = 0; row < numRows; row++)
                    {
                        chunk += matrix[row, col];
                    }

                    //adding the chunk if it matches
                    cipherChunks.Add(chunk);
                }


                //copying the cipherText in Another text

                string copyOfCipher = cipherText;


                //checking the key 

                keyFound = true;


                mainDic = new SortedDictionary<int, int>();
                foreach(string chunk in cipherChunks)
                {
                  
                    int x = copyOfCipher.IndexOf(chunk);

                    //checking if its found
                    if (x != -1)
                    {
                        mainDic.Add(x, cipherChunks.IndexOf(chunk) + 1);
                        copyOfCipher.Replace(chunk, "#");
                        
                    }
                    else
                    {
                        //now we want to get out of loop

                        keyFound = false;
                    }

                }
                
                //incrementing the keysize
                keySize++;
            } while (!keyFound);
            
            

            
            for (int chunk = 0; chunk < mainDic.Count; chunk++)
            {
                //adding it to the key


                keyDic.Add(mainDic.ElementAt(chunk).Value, chunk + 1);
            }

            for (int i = 1; i < keyDic.Count + 1; i++)
            {
                key.Add(keyDic[i]);
            }
            // Console.WriteLine(output);
            return key;


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
