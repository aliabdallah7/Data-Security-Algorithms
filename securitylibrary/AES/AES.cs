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
       public static string[,] previous_key = new string[4, 4];
        private static string[,] sBox = new string[,]
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

        private static string[,] Inverse_S_box = new string[16, 16] {

        {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
        {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
        {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95","0b", "42", "fa", "c3", "4e"},
        {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
        {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
        {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
        {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
        {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
        {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
        {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
        {"47", "f1","1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e","aa", "18", "be", "1b"},
        {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
        {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
        {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
        {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
        {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"}

        };


        private string[,] mixColumnMatrix = new string[,]
        {
            {"02","03", "01", "01"},
            {"01","02", "03", "01"},
            {"01","01", "02", "03"},
            {"03","01", "01", "02"}
        };




        private static string[,] Rcon = new string[,]
        {
            {"01","02","04","08","10","20","40","80","1b","36"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"}
        };


        public static string[,] ShiftRowsInverse(string[,] matrix)
        {
            string temp = "";
            int col = 3;

            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    temp = matrix[i, col];
                    matrix[i, col] = matrix[i, col - 1];
                    matrix[i, col - 1] = matrix[i, col - 2];
                    matrix[i, col - 2] = matrix[i, col - 3];
                    matrix[i, col - 3] = temp;
                }

            }

            Console.WriteLine("inverse shift rows before return ---->");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(matrix[i, j] + "  ");
                }
                Console.WriteLine();
            }

            return matrix;
        }
        public static string GetBinary(string x)
        {
            x = x.ToUpper();

            string result = "";

            for (int i = 0; i < x.Length; i++)
            {
                switch (x[i])
                {
                    case '0':
                        result += "0000";
                        break;
                    case '1':
                        result += "0001";
                        break;
                    case '2':
                        result += "0010";
                        break;
                    case '3':
                        result += "0011";
                        break;
                    case '4':
                        result += "0100";
                        break;
                    case '5':
                        result += "0101";
                        break;
                    case '6':
                        result += "0110";
                        break;
                    case '7':
                        result += "0111";
                        break;
                    case '8':
                        result += "1000";
                        break;
                    case '9':
                        result += "1001";
                        break;
                    case 'A':
                        result += "1010";
                        break;
                    case 'B':
                        result += "1011";
                        break;
                    case 'C':
                        result += "1100";
                        break;
                    case 'D':
                        result += "1101";
                        break;
                    case 'E':
                        result += "1110";
                        break;
                    case 'F':
                        result += "1111";
                        break;
                }
            }
            return result;
        }

        public static string GetHexa(string x)
        {

            string result = "";
            string[] r = new string[2];

            for (int i = 0; i < x.Length / 2; i++)
            {

                r[0] += x[i];
            }

            for (int i = 4; i < x.Length; i++)
            {
                r[1] += x[i];
            }

            for (int i = 0; i < r.Length; i++)
            {
                switch (r[i])
                {
                    case "0000":
                        result += "0";
                        break;
                    case "0001":
                        result += "1";
                        break;
                    case "0010":
                        result += "2";
                        break;
                    case "0011":
                        result += "3";
                        break;
                    case "0100":
                        result += "4";
                        break;
                    case "0101":
                        result += "5";
                        break;
                    case "0110":
                        result += "6";
                        break;
                    case "0111":
                        result += "7";
                        break;
                    case "1000":
                        result += "8";
                        break;
                    case "1001":
                        result += "9";
                        break;
                    case "1010":
                        result += "A";
                        break;
                    case "1011":
                        result += "B";
                        break;
                    case "1100":
                        result += "C";
                        break;
                    case "1101":
                        result += "D";
                        break;
                    case "1110":
                        result += "E";
                        break;
                    case "1111":
                        result += "F";
                        break;
                }
            }
            return result;
        }

        public static int[] GetDecimal(string s)
        {
            s = s.ToLower();

            int[] result = new int[2];

            string temp = "";

            for (int i = 0; i < 2; i++)
            {
                temp += s[i];
                switch (temp)
                {
                    case "a":
                        result[i] = 10;
                        break;
                    case "b":
                        result[i] = 11;
                        break;
                    case "c":
                        result[i] = 12;
                        break;
                    case "d":
                        result[i] = 13;
                        break;
                    case "e":
                        result[i] = 14;
                        break;
                    case "f":
                        result[i] = 15;
                        break;
                    default:
                        result[i] = Int16.Parse(temp);
                        break;
                }
                temp = "";
            }

            return result;
        }

        public static string[,] InverseSubBytes(string[,] matrix)
        {

            string[,] result = new string[4, 4];
            int[] indices = new int[2];
            string temp = "";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    matrix[i, j] = matrix[i, j].ToLower();

                    for (int k = 0; k < 2; k++)
                    {
                        temp += matrix[i, j][k];

                        switch (temp)
                        {
                            case "a":
                                indices[k] = 10;
                                break;
                            case "b":
                                indices[k] = 11;
                                break;
                            case "c":
                                indices[k] = 12;
                                break;
                            case "d":
                                indices[k] = 13;
                                break;
                            case "e":
                                indices[k] = 14;
                                break;
                            case "f":
                                indices[k] = 15;
                                break;
                            default:
                                indices[k] = Int16.Parse(temp);
                                break;
                        }
                        temp = "";
                    }

                    result[i, j] = Inverse_S_box[indices[0], indices[1]];
                }
            }

            return result;
        }
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

        public static string[,] SubBytesOneColumn(string[,] matrix)
        {
            string[,] result = new string[4, 1];
            int[] indices = new int[2];

            string temp = "";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 1; j++)
                {

                    matrix[i, j] = matrix[i, j].ToLower();

                    for (int k = 0; k < 2; k++)
                    {
                        temp += matrix[i, j][k];

                        switch (temp)
                        {
                            case "a":
                                indices[k] = 10;
                                break;
                            case "b":
                                indices[k] = 11;
                                break;
                            case "c":
                                indices[k] = 12;
                                break;
                            case "d":
                                indices[k] = 13;
                                break;
                            case "e":
                                indices[k] = 14;
                                break;
                            case "f":
                                indices[k] = 15;
                                break;
                            default:
                                indices[k] = Int16.Parse(temp);
                                break;
                        }
                        temp = "";
                    }

                    result[i, j] = sBox[indices[0], indices[1]];
                }
            }

            return result;
        }

        /// <summary>
        /// Computes the bitwise XOR operation between two hexadecimal strings.
        /// </summary>
        /// <param name="firstString">The first hexadecimal string.</param>
        /// <param name="secondString">The second hexadecimal string.</param>
        /// <returns>The resulting hexadecimal string of the XOR operation.</returns>
        public string XOR(string firstString, string secondString)
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

        public static string XORR(string s1, string s2)
        {
            string result = "";

            for (int i = 0; i < s1.Length; i++)
            {
                // 0001 0000
                // 1000 0010
                if (s1[i].CompareTo(s2[i]) == 0)
                {
                    result += "0";
                }
                else
                {
                    result += "1";
                }
            }

            return result;
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


        public static string[,] AddRoundKey(string[,] state, string[,] key)
        {
            string[,] ResultMatrix = new string[4, 4];

            string s, k, xor_result;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Converting to binary
                    s = GetBinary(state[i, j]);
                    k = GetBinary(key[i, j]);
                    // XORing the result
                    xor_result = XORR(s, k);
                    // Converting to hexadecimal
                    ResultMatrix[i, j] = GetHexa(xor_result);
                }
            }

            return ResultMatrix;
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


        public static string Multiply_By_0e(string s)
        {
            //((((x×2)+x)×2)+x)×2
            string result = XORR(Multiply_By_02(s), s);

            result = XORR(Multiply_By_02(result), s);
            result = Multiply_By_02(result);
            return result;
        }

        public static string Multiply_By_0d(string s)
        {
            //((((x×2)+x)×2)×2)+x
            string result = XORR(Multiply_By_02(s), s);

            result = Multiply_By_02(Multiply_By_02(result));
            result = XORR(result, s);

            return result;
        }

        public static string Multiply_By_0B(string s)
        {
            //((((x×2)×2)+x)×2)+x
            string result = Multiply_By_02(s);
            result = XORR(Multiply_By_02(result), s);
            result = XORR(Multiply_By_02(result), s);
            return result;
        }
        public static string Multiply_By_09(string s)
        {
            //(((x×2)×2)×2)+x
            string result = Multiply_By_02(s);
            result = Multiply_By_02(result);
            result = XORR(Multiply_By_02(result), s);
            return result;
        }

        public static string Multiply_By_01(string s)
        {
            return s;
        }

        public static string Multiply_By_02(string s)
        {

            string result = "";

            // 1000 0010
            string ms_bit = "";
            ms_bit += s[0];

            char[] char_arr = new char[s.Length];

            for (int i = 0; i < s.Length; i++)
            {
                char_arr[i] = s[i];
            }

            string shifted_s = "";

            for (int i = 0; i < s.Length; i++)
            {
                if (i == s.Length - 1)
                {
                    shifted_s += "0";
                }
                else
                {
                    char_arr[i] = char_arr[i + 1];
                    shifted_s += char_arr[i];
                }
            }

            result = shifted_s;

            string xor_result = "";

            if (ms_bit.Equals("1"))
            {
                xor_result = XORR(shifted_s, "00011011");
                result = xor_result;
            }
            else
            {
                result = shifted_s;
            }

            return result;

        }

        public static string Multiply_By_03(string s)
        {

            string result = "";

            result = Multiply_By_02(s);

            result = XORR(result, s);

            return result;
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
        public static string[,] MixColumnsInverse(string[,] matrix)
        {
            string[,] temp = new string[4, 4];
            string res = "";

            for (int cols = 0; cols < 4; cols++)
            {
                res = XORR(Multiply_By_0e(GetBinary(matrix[0, cols])), Multiply_By_0B(GetBinary(matrix[1, cols])));
                res = XORR(res, Multiply_By_0d(GetBinary(matrix[2, cols])));
                res = XORR(res, Multiply_By_09(GetBinary(matrix[3, cols])));

                temp[0, cols] = GetHexa(res);

                res = "";

                res = XORR(Multiply_By_09(GetBinary(matrix[0, cols])), Multiply_By_0e(GetBinary(matrix[1, cols])));
                res = XORR(res, Multiply_By_0B(GetBinary(matrix[2, cols])));
                res = XORR(res, Multiply_By_0d(GetBinary(matrix[3, cols])));

                temp[1, cols] = GetHexa(res);

                res = "";

                res = XORR(Multiply_By_0d(GetBinary(matrix[0, cols])), Multiply_By_09(GetBinary(matrix[1, cols])));
                res = XORR(res, Multiply_By_0e(GetBinary(matrix[2, cols])));
                res = XORR(res, Multiply_By_0B(GetBinary(matrix[3, cols])));

                temp[2, cols] = GetHexa(res);

                res = "";

                res = XORR(Multiply_By_0B(GetBinary(matrix[0, cols])), Multiply_By_0d(GetBinary(matrix[1, cols])));
                res = XORR(res, Multiply_By_09(GetBinary(matrix[2, cols])));
                res = XORR(res, Multiply_By_0e(GetBinary(matrix[3, cols])));

                temp[3, cols] = GetHexa(res);


            }

            return temp;

        }
        public static string[,] KeySchedule_GetFirstCoulmn(string[,] key, int round)
        {
            string[,] result = new string[4, 1];
            string[,] column_matrix = new string[4, 1];
            int lastcolumnIndex = 3, i = 0;
            string temp = "";


            // for the first column ONLY

            // take the last column rotating down once (RotWord)

            temp = key[i, lastcolumnIndex];
            key[i, lastcolumnIndex] = key[i + 1, lastcolumnIndex];
            key[i + 1, lastcolumnIndex] = key[i + 2, lastcolumnIndex];
            key[i + 2, lastcolumnIndex] = key[i + 3, lastcolumnIndex];
            key[i + 3, lastcolumnIndex] = temp;

            // Caling SubBytesOneColumn

            for (int j = 0; j < 4; j++)
            {
                column_matrix[j, 0] = key[j, lastcolumnIndex];
            }

            for (int k = 0; k < 4; k++)
            {
                Console.WriteLine(column_matrix[k, 0]);
            }
            column_matrix = SubBytesOneColumn(column_matrix);

            for (int l = 0; l < 4; l++)
            {
                Console.WriteLine(column_matrix[l, 0]);

            }
            // XOR three columns

            string[,] columnRcon = new string[4, 1];

            for (int k = 0; k < 4; k++)
            {
                columnRcon[k, 0] = Rcon[k, round];
            }

            string[,] key_column = new string[4, 1];

            for (int m = 0; m < 4; m++)
            {
                key_column[m, 0] = key[m, 0];
            }

            string s1, s2, s3, xor_result;

            for (int n = 0; n < 4; n++)
            {
                for (int l = 0; l < 1; l++)
                {
                    s1 = GetBinary(key_column[n, l]);
                    s2 = GetBinary(column_matrix[n, l]);
                    xor_result = XORR(s1, s2);

                    s3 = GetBinary(columnRcon[n, l]);
                    xor_result = XORR(xor_result, s3);

                    result[n, l] = GetHexa(xor_result);
                }
            }

            for (int n = 0; n < 4; n++)
            {

                Console.WriteLine(result[n, 0]);
            }

            return result;
        }

        public static string[,] Get_Second_Column(string[,] second_column_in_key, string[,] first_column_in_new_key)
        {

            string[,] second_column = new string[4, 1];

            string s1 = "", s2 = "", xor_result = "";

            for (int i = 0; i < 4; i++)
            {
                s1 = GetBinary(second_column_in_key[i, 0]);
                s2 = GetBinary(first_column_in_new_key[i, 0]);

                xor_result = XORR(s1, s2);

                second_column[i, 0] = GetHexa(xor_result);

            }

            return second_column;

        }

        public static string[,] Get_Third_Column(string[,] third_column_in_key, string[,] second_column_in_new_key)
        {

            string[,] third_column = new string[4, 1];

            string s1 = "", s2 = "", xor_result = "";

            for (int i = 0; i < 4; i++)
            {
                s1 = GetBinary(third_column_in_key[i, 0]);
                s2 = GetBinary(second_column_in_new_key[i, 0]);

                xor_result = XORR(s1, s2);

                third_column[i, 0] = GetHexa(xor_result);

            }

            return third_column;

        }

        public static string[,] Get_Fourth_Column(string[,] fourth_column_in_key, string[,] third_column_in_new_key)
        {

            string[,] fourth_column = new string[4, 1];

            string s1 = "", s2 = "", xor_result = "";

            for (int i = 0; i < 4; i++)
            {
                s1 = GetBinary(fourth_column_in_key[i, 0]);
                s2 = GetBinary(third_column_in_new_key[i, 0]);

                xor_result = XORR(s1, s2);

                fourth_column[i, 0] = GetHexa(xor_result);

            }

            return fourth_column;

        }

        public static string[,] KeySchedule(string[,] key_matrix, int round)
        {

            string[,] result = new string[4, 4];

            string[,] last_column = new string[4, 1];

            for (int i = 0; i < 4; i++)
            {
                last_column[i, 0] = key_matrix[i, 3];
            }

            // Get first Column

            string[,] first_column = new string[4, 1];

            first_column = KeySchedule_GetFirstCoulmn(key_matrix, round);

            Console.WriteLine("The first column : ");
            for (int i = 0; i < 4; i++)
            {
                result[i, 0] = first_column[i, 0];
            }

            // Get rest

            // Get second column

            string[,] second_column_in_key = new string[4, 1];
            for (int i = 0; i < 4; i++)
            {
                second_column_in_key[i, 0] = key_matrix[i, 1];
            }

            string[,] second_column_in_new_key = Get_Second_Column(second_column_in_key, first_column);

            for (int i = 0; i < 4; i++)
            {
                result[i, 1] = second_column_in_new_key[i, 0];
            }

            // Get third column

            string[,] third_column_in_key = new string[4, 1];
            for (int i = 0; i < 4; i++)
            {
                third_column_in_key[i, 0] = key_matrix[i, 2];
            }

            string[,] third_column_in_new_key = Get_Third_Column(third_column_in_key, second_column_in_new_key);

            for (int i = 0; i < 4; i++)
            {
                result[i, 2] = third_column_in_new_key[i, 0];
            }
            // Get fourth column

            string[,] fourth_column_in_new_key = Get_Fourth_Column(last_column, third_column_in_new_key);

            for (int i = 0; i < 4; i++)
            {
                result[i, 3] = fourth_column_in_new_key[i, 0];
            }

            Console.WriteLine("The result matrix: ");
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    Console.Write(result[row, col] + "  ");
                }
                Console.WriteLine();
            }

            previous_key = result;

            return result;

        }
        public override string Decrypt(string cipherText, string key)
        {
            

             string pl_txt = "0x";

            string[,] ct_matrix = new string[4, 4];

            string temp1 = "";

            int k = 2;

            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (k < cipherText.Length)
                    {
                        temp1 += cipherText[k];
                        temp1 += cipherText[k + 1];

                        ct_matrix[i, j] = temp1;
                        k += 2;
                        temp1 = "";
                    }

                }

            }

            k = 2;

            Console.WriteLine("The matrix of cipherText");

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(ct_matrix[i, j] + "   ");
                }
                Console.WriteLine();
            }

            string[,] key_matrix = new string[4, 4];
            string temp2 = "";

            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (k < key.Length)
                    {
                        temp2 += key[k];
                        temp2 += key[k + 1];

                        key_matrix[i, j] = temp2;
                        k += 2;
                        temp2 = "";
                    }

                }


            }
            Console.WriteLine("The matrix of key");

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(key_matrix[i, j] + "  ");
                }
                Console.WriteLine();
            }

            previous_key = key_matrix;

            string[,] round1key = new string[4, 4];
            string[,] round2key = new string[4, 4];
            string[,] round3key = new string[4, 4];
            string[,] round4key = new string[4, 4];
            string[,] round5key = new string[4, 4];
            string[,] round6key = new string[4, 4];
            string[,] round7key = new string[4, 4];
            string[,] round8key = new string[4, 4];
            string[,] round9key = new string[4, 4];
            string[,] round10key = new string[4, 4];

            Console.WriteLine("-------Observe from here the keys : ------");

            for (int i = 0; i < 10; i++)
            {
                if (i == 0)
                {

                    round1key = KeySchedule(previous_key,i);
                }
                else if (i == 1)
                {
                    round2key = KeySchedule(previous_key, i);
                }
                else if (i == 2)
                {
                    round3key = KeySchedule(previous_key, i);
                }
                else if (i == 3)
                {
                    round4key = KeySchedule(previous_key, i);
                }
                else if (i == 4)
                {
                    round5key = KeySchedule(previous_key, i);
                }
                else if (i == 5)
                {
                    round6key = KeySchedule(previous_key, i);
                }
                else if (i == 6)
                {
                    round7key = KeySchedule(previous_key, i);
                }
                else if (i == 7)
                {
                    round8key = KeySchedule(previous_key, i);
                }
                else if (i == 8)
                {
                    round9key = KeySchedule(previous_key, i);
                }
                else if (i == 9)
                {
                    round10key = KeySchedule(previous_key, i);
                }

            }



            Console.WriteLine("----------The end of keys : ------");

            // Add round key

            string[,] AddRoundKey_result = new string[4, 4];

            AddRoundKey_result = AddRoundKey(ct_matrix, round10key);

            Console.WriteLine("first Add round key : ----");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(AddRoundKey_result[i, j] + "  ");
                }
                Console.WriteLine();
            }

            string[,] input_of_invShiftRows = new string[4, 4];

            input_of_invShiftRows = AddRoundKey_result;

            string[,] InverseShiftRows_result = new string[4, 4];

            string[,] InverseSubBytes_result = new string[4, 4];

            string[,] inverseMixColumns_result = new string[4, 4];

            for (int i = 0; i < 9; i++)
            {
                // Inverse shift rows

                InverseShiftRows_result = ShiftRowsInverse(AddRoundKey_result);

                Console.WriteLine("inverse shift rows result round " + i + ": ----");

                for (int m = 0; m < 4; m++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Console.Write(InverseShiftRows_result[m, j] + "  ");
                    }
                    Console.WriteLine();
                }

                // Inverse sub bytes

                InverseSubBytes_result = InverseSubBytes(InverseShiftRows_result);

                Console.WriteLine("inverse sub bytes result round " + i + ": ----");

                for (int m = 0; m < 4; m++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Console.Write(InverseSubBytes_result[m, j] + "  ");
                    }
                    Console.WriteLine();
                }

                // Add round key

                Console.Write("roundkey 9 before switch: ----");
                for (int m = 0; m < 4; m++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Console.Write(round9key[m, j] + "  ");
                    }
                    Console.WriteLine();
                }

                string temp = "";
                int col = 3, row = 0;



                switch (i)
                {
                    case 0:
                        {
                            temp = round9key[row + 3, col];
                            round9key[row + 3, col] = round9key[row + 2, col];
                            round9key[row + 2, col] = round9key[row + 1, col];
                            round9key[row + 1, col] = round9key[row, col];
                            round9key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round9key);
                            break;
                        }
                    case 1:
                        {
                            temp = round8key[row + 3, col];
                            round8key[row + 3, col] = round8key[row + 2, col];
                            round8key[row + 2, col] = round8key[row + 1, col];
                            round8key[row + 1, col] = round8key[row, col];
                            round8key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round8key);
                            break;
                        }
                    case 2:
                        {
                            temp = round7key[row + 3, col];
                            round7key[row + 3, col] = round7key[row + 2, col];
                            round7key[row + 2, col] = round7key[row + 1, col];
                            round7key[row + 1, col] = round7key[row, col];
                            round7key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round7key);
                            break;
                        }
                    case 3:
                        {
                            temp = round6key[row + 3, col];
                            round6key[row + 3, col] = round6key[row + 2, col];
                            round6key[row + 2, col] = round6key[row + 1, col];
                            round6key[row + 1, col] = round6key[row, col];
                            round6key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round6key);
                            break;
                        }
                    case 4:
                        {
                            temp = round5key[row + 3, col];
                            round5key[row + 3, col] = round5key[row + 2, col];
                            round5key[row + 2, col] = round5key[row + 1, col];
                            round5key[row + 1, col] = round5key[row, col];
                            round5key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round5key);
                            break;
                        }
                    case 5:
                        {
                            temp = round4key[row + 3, col];
                            round4key[row + 3, col] = round4key[row + 2, col];
                            round4key[row + 2, col] = round4key[row + 1, col];
                            round4key[row + 1, col] = round4key[row, col];
                            round4key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round4key);
                            break;
                        }
                    case 6:
                        {
                            temp = round3key[row + 3, col];
                            round3key[row + 3, col] = round3key[row + 2, col];
                            round3key[row + 2, col] = round3key[row + 1, col];
                            round3key[row + 1, col] = round3key[row, col];
                            round3key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round3key);
                            break;
                        }
                    case 7:
                        {
                            temp = round2key[row + 3, col];
                            round2key[row + 3, col] = round2key[row + 2, col];
                            round2key[row + 2, col] = round2key[row + 1, col];
                            round2key[row + 1, col] = round2key[row, col];
                            round2key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round2key);
                            break;
                        }
                    case 8:
                        {
                            temp = round1key[row + 3, col];
                            round1key[row + 3, col] = round1key[row + 2, col];
                            round1key[row + 2, col] = round1key[row + 1, col];
                            round1key[row + 1, col] = round1key[row, col];
                            round1key[row, col] = temp;
                            temp = "";
                            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, round1key);
                            break;
                        }
                }

                for (int m = 0; m < 4; m++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Console.Write(round9key[m, j] + "  ");
                    }
                    Console.WriteLine();
                }

                for (int m = 0; m < 4; m++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Console.Write(AddRoundKey_result[m, j] + "  ");
                    }
                    Console.WriteLine();
                }

                // Inverse mix columns

                inverseMixColumns_result = MixColumnsInverse(AddRoundKey_result);

                Console.WriteLine("inverse mix columns result round " + i + ": ----");

                for (int m = 0; m < 4; m++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Console.Write(inverseMixColumns_result[m, j] + "  ");
                    }
                    Console.WriteLine();
                }

                AddRoundKey_result = inverseMixColumns_result;

            }

            // Inverse shift rows

            InverseShiftRows_result = ShiftRowsInverse(inverseMixColumns_result);

            Console.WriteLine("outer inverse shift rows result : ---");
            for (int m = 0; m < 4; m++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(InverseShiftRows_result[m, j] + "  ");
                }
                Console.WriteLine();
            }
            // Inverse sub bytes

            InverseSubBytes_result = InverseSubBytes(InverseShiftRows_result);
            Console.WriteLine("outer inverse sub bytes result : ---");
            for (int m = 0; m < 4; m++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(InverseSubBytes_result[m, j] + "  ");
                }
                Console.WriteLine();
            }
            // Add round key

            string t = "";
            int r = 0, c = 3;

            t = key_matrix[r + 3, c];
            key_matrix[r + 3, c] = key_matrix[r + 2, c];
            key_matrix[r + 2, c] = key_matrix[r + 1, c];
            key_matrix[r + 1, c] = key_matrix[r, c];
            key_matrix[r, c] = t;
            t = "";

            Console.WriteLine("outer key matrix result : ---");
            for (int m = 0; m < 4; m++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(key_matrix[m, j] + "  ");
                }
                Console.WriteLine();
            }

            AddRoundKey_result = AddRoundKey(InverseSubBytes_result, key_matrix);

            for (int j = 0; j < 4; j++)
            {
                for (int m = 0; m < 4; m++)
                {
                    pl_txt += AddRoundKey_result[m, j];
                }
            }

            return pl_txt;
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