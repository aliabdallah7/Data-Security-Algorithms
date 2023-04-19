using System;
using System.Globalization;
using System.Text;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private string[,] sBox = new string[,]
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




        private string[,] mixColumnMatrix = new string[,]
        {
            {"02","03", "01", "01"},
            {"01","02", "03", "01"},
            {"01","01", "02", "03"},
            {"03","01", "01", "02"}
        };




        private string[,] Rcon = new string[,]
        {
            {"01","02","04","08","10","20","40","80","1b","36"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"}
        };



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



        private string[,] SubBytes(string[,] matrix, string[,] box)
        {
            // Check that the input matrices have the correct dimensions
            if (matrix.GetLength(0) != 4 || matrix.GetLength(1) != 4 ||
                box.GetLength(0) != 16 || box.GetLength(1) != 16)
            {
                throw new ArgumentException("Input matrices must have dimensions 4x4 and 16x16, respectively");
            }

            // Create a new 4x4 matrix to store the output
            string[,] result = new string[4, 4];

            // Iterate over each byte in the input matrix
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Get the hexadecimal string value of the current byte in the input matrix
                    string hex = matrix[i, j];

                    // Parse the row and column values from the hexadecimal string
                    int row = int.Parse(hex[0].ToString(), NumberStyles.HexNumber);
                    int col = int.Parse(hex[1].ToString(), NumberStyles.HexNumber);

                    // Look up the corresponding byte value from the substitution box matrix
                    result[i, j] = box[row, col];
                }
            }

            // Return the output matrix
            return result;
        }


        /// <summary>
        /// Replaces each element of the given string array with the corresponding element in the given substitution box.
        /// </summary>
        /// <param name="array">The string array to substitute.</param>
        /// <param name="box">The substitution box to use.</param>
        /// <returns>The substituted string array.</returns>
        private string[] SubBytes(string[] array, string[,] box)
        {
            // Iterate over each element of the given string array.
            for (int i = 0; i < 4; i++)
            {
                // Get the current element and convert it to row and column indices.
                string temp = array[i];
                int row = (int)Convert.ToInt32(temp[0].ToString(), 16);
                int col = (int)Convert.ToInt32(temp[1].ToString(), 16);

                // Replace the current element with the corresponding element from the substitution box.
                array[i] = box[row, col];
            }

            // Return the substituted string array.
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



        /// <summary>
        /// Computes the bitwise XOR operation between two hexadecimal strings.
        /// </summary>
        /// <param name="firstString">The first hexadecimal string.</param>
        /// <param name="secondString">The second hexadecimal string.</param>
        /// <returns>The resulting hexadecimal string of the XOR operation.</returns>
        private string XOR(string firstString, string secondString)
        {
            // Convert the first hexadecimal string to an integer.
            int first = Convert.ToInt32(firstString, 16);

            // Convert the second hexadecimal string to an integer.
            int second = Convert.ToInt32(secondString, 16);

            // Compute the bitwise XOR operation between the two integers.
            int xorResult = first ^ second;

            // Convert the resulting integer to a hexadecimal string.
            string result = Convert.ToString(xorResult, 16);

            // Pad the resulting hexadecimal string with a leading zero if necessary.
            return result.PadLeft(2, '0');
        }


        /// <summary>
        /// Rotates the elements of the given string array one position to the left.
        /// </summary>
        /// <param name="column">The string array to rotate.</param>
        /// <returns>The rotated string array.</returns>
        private string[] RotateWord(string[] column)
        {
            // If the given string array is null or doesn't have exactly 4 elements, return it as is.
            if (column == null || column.Length != 4)
            {
                return column;
            }

            // Create a new string array to hold the rotated elements.
            string[] rotatedColumn = new string[4];

            // Copy the elements to the new array in a rotated order.
            rotatedColumn[0] = column[1];
            rotatedColumn[1] = column[2];
            rotatedColumn[2] = column[3];
            rotatedColumn[3] = column[0];

            // Return the rotated string array.
            return rotatedColumn;
        }


        private string[,] KeySchedule(string[,] key)
        {
            // Create a 4x44 matrix to hold the key schedule
            string[,] keySchedule = new string[4, 44];

            // Copy the original key into the first 4 columns of the key schedule
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keySchedule[j, i] = key[j, i];
                }
            }

            // Iterate through the remaining columns of the key schedule
            for (int i = 4; i < 44; i++)
            {
                // Initialize two temporary columns to hold values from the previous column and from 4 columns ago
                string[] column1 = new string[4];
                string[] column2 = new string[4];

                // Copy the values from the previous column and from 4 columns ago into the temporary columns
                for (int k = 0; k < 4; k++)
                {
                    column1[k] = keySchedule[k, i - 1];
                    column2[k] = keySchedule[k, i - 4];
                }

                // If the current column is a multiple of 4, perform key schedule core operations on column1
                if (i % 4 == 0)
                {
                    // Rotate column1 by 1 byte
                    column1 = RotateWord(column1);

                    // Substitute each byte of column1 with a value from the S-box lookup table
                    column1 = SubBytes(column1, sBox);

                    // Get the appropriate value from the Rcon lookup table based on the current column and create a new column
                    string[] RconColumn = new string[4];
                    for (int j = 0; j < 4; j++)
                    {
                        RconColumn[j] = Rcon[j, (i / 4) - 1];
                    }

                    // XOR column1 with column2, then XOR the result with the Rcon column, and store the result in the key schedule
                    for (int j = 0; j < 4; j++)
                    {
                        column1[j] = XOR(column1[j], column2[j]);
                        keySchedule[j, i] = XOR(column1[j], RconColumn[j]);
                    }
                }
                // If the current column is not a multiple of 4, simply XOR column1 with column2 and store the result in the key schedule
                else
                {
                    for (int j = 0; j < 4; j++)
                    {
                        keySchedule[j, i] = XOR(column1[j], column2[j]);
                    }
                }
            }

            // Return the completed key schedule
            return keySchedule;
        }



        /// <summary>
        /// Extracts the round key for the given round from the key schedule matrix.
        /// </summary>
        /// <param name="keySchedule">The key schedule matrix.</param>
        /// <param name="round">The round number (0-based).</param>
        /// <returns>The round key matrix.</returns>
        private string[,] roundKey(string[,] keySchedule, int round)
        {
            // Create a new 4x4 matrix to hold the round key.
            string[,] matrix = new string[4, 4];

            // Extract each column of the round key from the key schedule matrix.
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Compute the index of the element in the key schedule matrix.
                    int index = round * 4 + i;

                    // Extract the element from the key schedule matrix and store it in the round key matrix.
                    matrix[j, i] = keySchedule[j, index];
                }
            }

            // Return the round key matrix.
            return matrix;
        }



        /// <summary>
        /// Computes the bitwise XOR operation between two binary strings.
        /// </summary>
        /// <param name="binaryStr1">The first binary string.</param>
        /// <param name="binaryStr2">The second binary string.</param>
        /// <returns>The resulting binary string of the XOR operation.</returns>
        private string XORBinary(string binaryStr1, string binaryStr2)
        {
            // Initialize an empty string to hold the result of the XOR operation.
            string result = "";

            // Check if both binary strings are non-empty.
            if (binaryStr1 != "" && binaryStr2 != "")
            {
                // Perform the XOR operation on each bit of the binary strings.
                for (int i = 0; i < 8; i++)
                {
                    if (binaryStr1[i] == '0' && binaryStr2[i] == '0')
                    {
                        result += '0';
                    }
                    else if (binaryStr1[i] == '1' && binaryStr2[i] == '1')
                    {
                        result += '0';
                    }
                    else
                    {
                        result += '1';
                    }
                }
            }
            // If one of the binary strings is empty, set the result to the other string.
            else if (binaryStr1 == "")
            {
                result = binaryStr2;
            }
            else if (binaryStr2 == "")
            {
                result = binaryStr1;
            }

            // Return the resulting binary string.
            return result;
        }



        /// <summary>
        /// Shifts the bits of the given binary string one position to the left.
        /// </summary>
        /// <param name="binarystr">The binary string to shift.</param>
        /// <returns>The shifted binary string.</returns>
        private string ShiftLeft(StringBuilder binarystr)
        {
            // Iterate through each bit of the binary string.
            for (int i = 0; i < 8; i++)
            {
                // If we are at the last bit, set it to 0.
                if (i == 7)
                {
                    binarystr[7] = '0';
                }
                // Otherwise, shift the bit one position to the left.
                else
                {
                    binarystr[i] = binarystr[i + 1];
                }
            }

            // Convert the shifted binary string to a regular string and return it.
            return binarystr.ToString();
        }



        /* This function takes a 4x4 matrix of hexadecimal strings as input
           and returns a new matrix after performing the MixColumns operation
        */
        private string[,] MixColumns(string[,] matrix)
        {
            // Create a new 4x4 matrix to store the result
            string[,] result = new string[4, 4]
            {
                { "", "", "", "" },
                { "", "", "", "" },
                { "", "", "", "" },
                { "", "", "", "" }
            };


            // Loop through each column of the matrix
            for (int i = 0; i < 4; i++)
            {
                // Loop through each row of the column
                for (int j = 0; j < 4; j++)
                {
                    // Loop through each element of the MixColumnMatrix
                    for (int k = 0; k < 4; k++)
                    {
                        // Convert the hexadecimal string to a binary string and pad it with zeros to make it 8 bits long
                        StringBuilder binary1 = new StringBuilder(Convert.ToString(Convert.ToInt32(matrix[k, j].ToString(), 16), 2).PadLeft(8, '0'));

                        // Initialize variables to store intermediate results
                        string res = "";
                        string _1B = Convert.ToString(Convert.ToInt32("1B".ToString(), 16), 2).PadLeft(8, '0');

                        // Check the value of the current element of the MixColumnMatrix
                        if (mixColumnMatrix[i, k].Equals("02"))
                        {
                            // If the value is "02", perform the appropriate operations on the binary string
                            if (binary1[0] == '1')
                            {
                                // If the leftmost bit is 1, shift the binary string to the left and XOR it with the value "1B" in binary
                                ShiftLeft(binary1);
                                res = XORBinary(XORBinary(binary1.ToString(), _1B), res);
                            }
                            else
                            {
                                // If the leftmost bit is 0, simply shift the binary string to the left
                                res = ShiftLeft(binary1);
                            }
                        }
                        else if (mixColumnMatrix[i, k].Equals("01"))
                        {
                            // If the value is "01", simply copy the binary string to the result
                            res = binary1.ToString();
                        }
                        else if (mixColumnMatrix[i, k].Equals("03"))
                        {
                            // If the value is "03", perform the appropriate operations on the binary string
                            res = binary1.ToString();
                            if (binary1[0] == '1')
                            {
                                // If the leftmost bit is 1, shift the binary string to the left and XOR it with the value "1B" in binary
                                ShiftLeft(binary1);
                                res = XORBinary(XORBinary(binary1.ToString(), _1B), res);
                            }
                            else
                            {
                                // If the leftmost bit is 0, simply shift the binary string to the left
                                ShiftLeft(binary1);
                                res = XORBinary(binary1.ToString(), res);
                            }
                        }

                        // XOR the result with the corresponding element of the mixed matrix
                        result[i, j] = XORBinary(result[i, j].PadLeft(8, '0'), res);

                        // If we have processed the last element of the MixColumnMatrix for this column, convert the binary result to a hexadecimal string
                        if (k == 3)
                        {
                            result[i, j] = Convert.ToString(Convert.ToInt32(result[i, j].ToString(), 2), 16).PadLeft(2, '0').ToUpper();
                        }
                    }
                }
            }

            // Return the matrix after performing 'Mix Columns' Operation
            return result;
        }




        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }



        public override string Encrypt(string plainText, string key)
        {
            // Convert plain text and key strings into matrices
            string[,] plainTextMatrix = stringToMatrix(plainText);
            string[,] keyMatrix = stringToMatrix(key);

            // Generate key schedule matrix using key matrix
            string[,] key_schedule = KeySchedule(keyMatrix);

            // Start building the result string
            string result = "0x";

            // XOR the plain text matrix with the first round key
            plainTextMatrix = XOR(plainTextMatrix, roundKey(key_schedule, 0));

            // Perform 10 rounds of operations on the plain text matrix
            for (int i = 0; i < 10; i++)
            {
                // Substitute bytes in the plain text matrix using the s-box matrix
                plainTextMatrix = SubBytes(plainTextMatrix, sBox);

                // Shift rows of the plain text matrix to the left by a varying number of bytes
                plainTextMatrix = shiftRowsLeft(plainTextMatrix);

                // Mix columns of the plain text matrix using a specific multiplication method (except for the last round)
                if (i != 9)
                    plainTextMatrix = MixColumns(plainTextMatrix);

                // XOR the plain text matrix with the next round key
                plainTextMatrix = XOR(plainTextMatrix, roundKey(key_schedule, i + 1));
            }

            // Build the result string by appending each element of the plain text matrix
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += plainTextMatrix[j, i];
                }
            }

            // Return the result string
            return result;
        }

    }
}