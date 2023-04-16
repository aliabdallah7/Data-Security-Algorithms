using System;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        string[,] sBox = new string[,]
        {
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
        };




        string[,] mixColumnMatrix = new string[,]
        {
            {"02","03", "01", "01"},
            {"01","02", "03", "01"},
            {"01","01", "02", "03"},
            {"03","01", "01", "02"}
        };




        string[,] Rcon = new string[,]{
        {"01","02","04","08","10","20","40","80","1b","36"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"}};



        // This function takes a string as input and returns a 2D string array.
        private string[,] stringToMatrix(string textString)
        {
            // Initialize a new 2D string array with 4 rows and 4 columns to hold the characters from the input string in a matrix format.
            string[,] matrix = new string[4, 4];

            // Convert the input string to a character array.
            char[] CharArr = textString.ToCharArray();

            // Initialize a count variable with the value 2 to keep track of the current index in the character array.
            int count = 2;

            // Use nested for loops to iterate over each element in the matrix.
            // The outer loop iterates over the rows, while the inner loop iterates over the columns.
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Assign a value to the current element in the matrix by concatenating two characters from the character array.
                    // The count variable is used to keep track of the current index in the character array, and is incremented by 2 after each assignment to move to the next set of two characters.
                    matrix[j, i] = CharArr[count] + "" + CharArr[count + 1];
                    count += 2;
                }
            }

            // Return the 2D string array containing the characters from the input string arranged in a 4x4 matrix format.
            return matrix;
        }


        private string[,] shiftRowsLeft(string[,] matrix)
        {
            // Get the number of rows and columns in the input matrix
            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);

            // Create a new matrix to hold the shifted rows
            string[,] result = new string[rows, cols];

            // Loop through each element in the matrix
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    // Compute the new column index after shifting left
                    // This formula adds the number of rows to the current row index
                    // to shift the elements left, and then takes the result modulo
                    // the number of columns to ensure the new column index is within
                    // the bounds of the matrix
                    int newCol = (j + rows - i) % cols;

                    // Copy the element from the input matrix to the corresponding
                    // position in the result matrix using the new row and column indices
                    result[i, newCol] = matrix[i, j];
                }
            }

            // Return the matrix with the shifted rows
            return result;
        }


        private string[] substituteBytes(string[] array, string[,] sbox)
        {
            for (int i = 0; i < 4; i++)
            {
                string temp = array[i];
                int row = (int)Convert.ToInt32(temp[0].ToString(), 16);
                int col = (int)Convert.ToInt32(temp[1].ToString(), 16);
                array[i] = sbox[row, col];
            }

            return array;
        }

        private string[,] XOR(string[,] firstString, string[,] secondString)
        {
            // Initialize a new 4x4 matrix to hold the XOR result
            string[,] result = new string[4, 4];

            for (int i = 0; i < 4; i++) // Loop through each row of the matrices
            {
                for (int j = 0; j < 4; j++) // Loop through each column of the matrices
                {
                    // Convert the hex strings to int values using the base-16 (hexadecimal) representation
                    int first = Convert.ToInt32(firstString[i, j], 16);
                    int second = Convert.ToInt32(secondString[i, j], 16);

                    // Perform XOR operation on the two int values
                    int xorResult = first ^ second;

                    // Convert the XOR result back to a hex string with a minimum length of two characters and store it in the result matrix
                    result[i, j] = xorResult.ToString("X2");
                }
            }

            // Return the result matrix
            return result;
        }



        private string XOR(string firstString, string secondString)
        {
            int first = Convert.ToInt32(firstString, 16);
            int second = Convert.ToInt32(secondString, 16);
            int xorResult = first ^ second;

            string result = Convert.ToString(xorResult, 16);

            return result.PadLeft(2, '0');
        }


        private string[] RotateWord(string[] column)
        {
            if (column == null || column.Length != 4)
            {
                return column;
            }

            string[] rotatedColumn = new string[4];

            rotatedColumn[0] = column[1];
            rotatedColumn[1] = column[2];
            rotatedColumn[2] = column[3];
            rotatedColumn[3] = column[0];

            return rotatedColumn;
        }

        // This is a private method called KeySchedule that takes a 4x4 string array as input.
        // It returns a 4x44 string array as output.
        private string[,] KeySchedule(string[,] key)
        {
            // Create a 4x44 string array called keySchedule.
            string[,] keySchedule = new string[4, 44];

            // Copy the first 4 columns of the input key to the first 4 columns of keySchedule.
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keySchedule[j, i] = key[j, i];
                }
            }

            // Iterate through the remaining 40 columns of keySchedule.
            for (int i = 4; i < 44; i++)
            {
                // Create two temporary arrays called column1 and column2.
                string[] column1 = new string[4];
                string[] column2 = new string[4];

                // Copy the previous column (i-1) to column1 and the column 4 places behind (i-4) to column2.
                for (int k = 0; k < 4; k++)
                {
                    column1[k] = keySchedule[k, i - 1];
                    column2[k] = keySchedule[k, i - 4];
                }

                // If the current column is a multiple of 4 (i.e. 4, 8, 12, ...), perform a series of operations.
                if (i % 4 == 0)
                {
                    // Rotate the bytes in column1 one position to the left.
                    column1 = RotateWord(column1);

                    // Substitute each byte in column1 using an S-box lookup table called sBox.
                    column1 = substituteBytes(column1, sBox);

                    // Create a new temporary array called RconColumn by looking up a value from a table called Rcon.
                    string[] RconColumn = new string[4];
                    for (int j = 0; j < 4; j++)
                    {
                        RconColumn[j] = Rcon[j, (i / 4) - 1];
                    }

                    // Perform an XOR operation on each byte in column1 with the corresponding byte in column2.
                    // Then perform another XOR operation on each byte in the result with the corresponding byte in RconColumn.
                    // Store the final result in the current column of keySchedule.
                    for (int j = 0; j < 4; j++)
                    {
                        column1[j] = XOR(column1[j], column2[j]);
                        keySchedule[j, i] = XOR(column1[j], RconColumn[j]);
                    }

                }
                // If the current column is not a multiple of 4, perform a simpler operation.
                else
                {
                    // Perform an XOR operation on each byte in column1 with the corresponding byte in column2.
                    // Store the result in the current column of keySchedule.
                    for (int j = 0; j < 4; j++)
                    {
                        keySchedule[j, i] = XOR(column1[j], column2[j]);
                    }
                }
            }

            // Return the final 4x44 keySchedule.
            return keySchedule;
        }




        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
    }
}