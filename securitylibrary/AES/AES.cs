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
            string temporary = "";
            int lastColumnIndex = 3;

            // While loop to iterate over the rows of the matrix
            int rowIndex = 1;
            while (rowIndex < 4)
            {
                // For loop to iterate over each element in the current row up to the current row index
                for (int shiftIndex = 0; shiftIndex < rowIndex; shiftIndex++)
                {
                    temporary = matrix[rowIndex, lastColumnIndex];
                    matrix[rowIndex, lastColumnIndex] = matrix[rowIndex, lastColumnIndex - 1];
                    matrix[rowIndex, lastColumnIndex - 1] = matrix[rowIndex, lastColumnIndex - 2];
                    matrix[rowIndex, lastColumnIndex - 2] = matrix[rowIndex, lastColumnIndex - 3];
                    matrix[rowIndex, lastColumnIndex - 3] = temporary;
                }

                // Increment the row index after processing the current row
                rowIndex++;
            }

            return matrix;
        }
        public static string getBin(string inputString)
        {
            // Convert the input string to uppercase for consistency
            inputString = inputString.ToUpper();

            // Create an empty string to hold the binary representation
            string binaryString = "";

            // Loop over each character in the input string
            int i = 0;
            while (i < inputString.Length)
            {
                // Use a switch statement to map each hexadecimal digit to its corresponding binary representation
                switch (inputString[i])
                {
                    case '0':
                        binaryString += "0000";
                        break;
                    case '1':
                        binaryString += "0001";
                        break;
                    case '2':
                        binaryString += "0010";
                        break;
                    case '3':
                        binaryString += "0011";
                        break;
                    case '4':
                        binaryString += "0100";
                        break;
                    case '5':
                        binaryString += "0101";
                        break;
                    case '6':
                        binaryString += "0110";
                        break;
                    case '7':
                        binaryString += "0111";
                        break;
                    case '8':
                        binaryString += "1000";
                        break;
                    case '9':
                        binaryString += "1001";
                        break;
                    case 'A':
                        binaryString += "1010";
                        break;
                    case 'B':
                        binaryString += "1011";
                        break;
                    case 'C':
                        binaryString += "1100";
                        break;
                    case 'D':
                        binaryString += "1101";
                        break;
                    case 'E':
                        binaryString += "1110";
                        break;
                    case 'F':
                        binaryString += "1111";
                        break;
                }
                // Increment the loop counter by the length of the binary representation for the current hexadecimal digit
                i += 1;
            }

            // Return the binary representation of the input string
            return binaryString;
        }

        public static string getHex(string hex)
        {

            string result = "";
            string[] substrings = new string[2];

            // Extract first half of input string
            int i = 0;
            while (i < hex.Length / 2)
            {
                substrings[0] += hex[i];
                i++;
            }

            // Extract second half of input string
            int j = hex.Length / 2;
            while (j < hex.Length)
            {
                substrings[1] += hex[j];
                j++;
            }

            // Convert each substring to decimal and append to result string
            for (int k = 0; k < substrings.Length; k++)
            {
                switch (substrings[k])
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

        public static int[] getDec(string hex)
        {
            // Convert the input to lowercase for consistency
            hex = hex.ToLower();

            // Create an array of two integers to store the output
            int[] res = new int[2];

            // Create a temporary string to hold each hex digit as we process it
            string temp = "";

            // Loop through each pair of hex digits and convert them to decimal
            int i = 0;
            while (i < 2)
            {
                // Add the next hex digit to the temporary string
                temp += hex[i];

                // Convert the temporary string to decimal based on the hex digit
                switch (temp)
                {
                    case "a":
                        res[i] = 10;
                        break;
                    case "b":
                        res[i] = 11;
                        break;
                    case "c":
                        res[i] = 12;
                        break;
                    case "d":
                        res[i] = 13;
                        break;
                    case "e":
                        res[i] = 14;
                        break;
                    case "f":
                        res[i] = 15;
                        break;
                    default:
                        res[i] = Int16.Parse(temp);
                        break;
                }

                // Reset the temporary string for the next pair of hex digits
                temp = "";

                // Move to the next pair of hex digits
                i++;
            }

            // Return the array of decimal integers
            return res;
        }
        public static string[,] InverseSubBytes(string[,] inputMatrix)
        {
            // Create a new 4x4 matrix to store the result
            string[,] resultMatrix = new string[4, 4];

            // Create an array to store the indices of the current byte in the S-box
            int[] byteIndices = new int[2];

            // Create a temporary string to store each byte as it is processed
            string tempByte = "";

            // Loop through each byte in the input matrix
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    // Convert the byte to lowercase
                    inputMatrix[i, j] = inputMatrix[i, j].ToLower();

                    // Loop through each character in the byte
                    int k = 0;
                    while (k < 2)
                    {
                        // Add the current character to the temporary string
                        tempByte += inputMatrix[i, j][k];

                        // Look up the index of the byte in the S-box
                        switch (tempByte)
                        {
                            case "a":
                                byteIndices[k] = 10;
                                break;
                            case "b":
                                byteIndices[k] = 11;
                                break;
                            case "c":
                                byteIndices[k] = 12;
                                break;
                            case "d":
                                byteIndices[k] = 13;
                                break;
                            case "e":
                                byteIndices[k] = 14;
                                break;
                            case "f":
                                byteIndices[k] = 15;
                                break;
                            default:
                                byteIndices[k] = Int16.Parse(tempByte);
                                break;
                        }

                        // Reset the temporary string
                        tempByte = "";

                        // Move on to the next character in the byte
                        k++;
                    }

                    // Look up the byte in the inverse S-box and store it in the result matrix
                    resultMatrix[i, j] = Inverse_S_box[byteIndices[0], byteIndices[1]];

                    // Move on to the next byte in the matrix
                    j++;
                }
                i++;
            }

            // Return the result matrix
            return resultMatrix;
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

        /*
 SubBytesOneColumn takes a 4x1 matrix as an input and applies a substitution operation to each element of the matrix using the S-box.
 The result is a new 4x1 matrix with each element replaced by its corresponding value in the S-box.
 */

        public static string[,] subBytes1Col(string[,] inputMatrix)
        {
            string[,] resultMatrix = new string[4, 1];
            int[] indices = new int[2];
            string temp = "";
            for (int i = 0; i < 4; i++)
            {
                // loop through each row and the first column of the matrix
                for (int j = 0; j < 1; j++)
                {
                    // convert the element to lowercase
                    inputMatrix[i, j] = inputMatrix[i, j].ToLower();

                    // loop through each character of the element
                    for (int k = 0; k < 2; k++)
                    {
                        temp += inputMatrix[i, j][k];

                        // check if the character is a letter from A to F
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

                    // replace the element with its corresponding value in the S-box
                    resultMatrix[i, j] = sBox[indices[0], indices[1]];
                }
            }

            return resultMatrix;
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


        public static string[,] AddRoundKey(string[,] stateMatrix, string[,] keyMatrix)
        {
            // Initialize an empty 4x4 matrix to hold the result
            string[,] resultMatrix = new string[4, 4];

            string stateValue, keyValue, xorResult;

            // Loop through each element of the matrix
            for (int row = 0; row < 4; row++)
            {
                for (int column = 0; column < 4; column++)
                {
                    // Convert the values to binary
                    stateValue = getBin(stateMatrix[row, column]);
                    keyValue = getBin(keyMatrix[row, column]);

                    // XOR the binary values
                    xorResult = XORR(stateValue, keyValue);

                    // Convert the result back to hexadecimal and store it in the result matrix
                    resultMatrix[row, column] = getHex(xorResult);
                }
            }

            return resultMatrix;
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


        // Function to multiply a given string by 0e
        public static string MultiplyBy0e(string input)
        {
            // ((((x×2)+x)×2)+x)×2
            string result = XORR(MultiplyBy02(input), input);

            result = XORR(MultiplyBy02(result), input);
            result = MultiplyBy02(result);
            return result;
        }

        // Function to multiply a given string by 0d
        public static string MultiplyBy0d(string input)
        {
            // ((((x×2)+x)×2)×2)+x
            string result = XORR(MultiplyBy02(input), input);

            result = MultiplyBy02(MultiplyBy02(result));
            result = XORR(result, input);

            return result;
        }

        // Function to multiply a given string by 0B
        public static string MultiplyBy0B(string input)
        {
            // ((((x×2)×2)+x)×2)+x
            string result = MultiplyBy02(input);
            result = XORR(MultiplyBy02(result), input);
            result = XORR(MultiplyBy02(result), input);
            return result;
        }

        // Function to multiply a given string by 09
        public static string MultiplyBy09(string input)
        {
            // (((x×2)×2)×2)+x
            string result = MultiplyBy02(input);
            result = MultiplyBy02(result);
            result = XORR(MultiplyBy02(result), input);
            return result;
        }

        // Function to multiply a given string by 01
        public static string MultiplyBy01(string input)
        {
            return input;
        }

        // Function to multiply a given string by 02
        public static string MultiplyBy02(string input)
        {
            string result = "";

            // 1000 0010
            string msBit = "";
            msBit += input[0];

            char[] charArr = new char[input.Length];

            // Convert input string to char array
            for (int i = 0; i < input.Length; i++)
            {
                charArr[i] = input[i];
            }

            string shiftedInput = "";

            // Shift input string to the left by one bit
            for (int i = 0; i < input.Length; i++)
            {
                if (i == input.Length - 1)
                {
                    shiftedInput += "0";
                }
                else
                {
                    charArr[i] = charArr[i + 1];
                    shiftedInput += charArr[i];
                }
            }

            result = shiftedInput;

            string xorResult = "";

            // XOR result with 00011011 if msBit is 1
            if (msBit.Equals("1"))
            {
                xorResult = XORR(shiftedInput, "00011011");
                result = xorResult;
            }
            else
            {
                result = shiftedInput;
            }

            return result;
        }

        //multiplies the given string by 03
        public static string MultiplyStringBy03(string givenString)
        {
            //storing the result
            string resultantString = "";

            resultantString = MultiplyBy02(givenString);

            resultantString = XORR(resultantString, givenString);

            return resultantString;
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


        //Mix the inverse of columns
        public static string[,] MixColsInverse(string[,] matrixToBeMixed)
        {
            //store the result in an empty string
            string result = "";

            //store the temporary result
            string[,] tempResult = new string[4, 4];

            // initialize variable to keep track of current column
            int cols = 0;

            // loop through columns of matrix
            while (cols < 4)
            {
                // calculate and store first row of mixed matrix
                result = XORR(MultiplyBy0e(getBin(matrixToBeMixed[0, cols])), MultiplyBy0B(getBin(matrixToBeMixed[1, cols])));
                result = XORR(result, MultiplyBy0d(getBin(matrixToBeMixed[2, cols])));
                result = XORR(result, MultiplyBy09(getBin(matrixToBeMixed[3, cols])));
                tempResult[0, cols] = getHex(result);

                // reset result string
                result = "";

                // calculate and store second row of mixed matrix
                result = XORR(MultiplyBy09(getBin(matrixToBeMixed[0, cols])), MultiplyBy0e(getBin(matrixToBeMixed[1, cols])));
                result = XORR(result, MultiplyBy0B(getBin(matrixToBeMixed[2, cols])));
                result = XORR(result, MultiplyBy0d(getBin(matrixToBeMixed[3, cols])));
                tempResult[1, cols] = getHex(result);

                // reset result string
                result = "";

                // calculate and store third row of mixed matrix
                result = XORR(MultiplyBy0d(getBin(matrixToBeMixed[0, cols])), MultiplyBy09(getBin(matrixToBeMixed[1, cols])));
                result = XORR(result, MultiplyBy0e(getBin(matrixToBeMixed[2, cols])));
                result = XORR(result, MultiplyBy0B(getBin(matrixToBeMixed[3, cols])));
                tempResult[2, cols] = getHex(result);

                // reset result string
                result = "";

                // calculate and store fourth row of mixed matrix
                result = XORR(MultiplyBy0B(getBin(matrixToBeMixed[0, cols])), MultiplyBy0d(getBin(matrixToBeMixed[1, cols])));
                result = XORR(result, MultiplyBy09(getBin(matrixToBeMixed[2, cols])));
                result = XORR(result, MultiplyBy0e(getBin(matrixToBeMixed[3, cols])));
                tempResult[3, cols] = getHex(result);

                // increment current column
                cols++;
            }


            return tempResult;

        }
        /// <summary>
        /// Given a 4x4 key matrix and a round number, returns the first column of the key schedule matrix for that round.
        /// </summary>
        /// <param name="keyMatrix">A 4x4 key matrix.</param>
        /// <param name="roundNumber">The round number for which to generate the key schedule.</param>
        /// <returns>The first column of the key schedule matrix for the specified round.</returns>
        public static string[,] GetKeyScheduleFirstColumn(string[,] keyMatrix, int roundNumber)
        {
            //the
            string[,] columnMatrix = new string[4, 1];
            //the index of the last column
            int lastColumnIndex = 3;
            //index for the loop
            int i = 0;
            //temporary
            string temp = "";
            //result
            string[,] result = new string[4, 1];
            // Generate the first column of the key schedule matrix for the specified round.

            // Take the last column of the key matrix and rotate it down by one position.
            temp = keyMatrix[i, lastColumnIndex];
            keyMatrix[i, lastColumnIndex] = keyMatrix[i + 1, lastColumnIndex];
            keyMatrix[i + 1, lastColumnIndex] = keyMatrix[i + 2, lastColumnIndex];
            keyMatrix[i + 2, lastColumnIndex] = keyMatrix[i + 3, lastColumnIndex];
            keyMatrix[i + 3, lastColumnIndex] = temp;

            // Apply the SubBytesOneColumn function to the rotated column.
            for (int j = 0; j < 4; j++)
            {
                columnMatrix[j, 0] = keyMatrix[j, lastColumnIndex];
            }

            columnMatrix = subBytes1Col(columnMatrix);

            // XOR the rotated column with the Rcon value for the current round.
            string[,] columnRcon = new string[4, 1];

            for (int k = 0; k < 4; k++)
            {
                columnRcon[k, 0] = Rcon[k, roundNumber];
            }

            string[,] keyColumn = new string[4, 1];

            for (int m = 0; m < 4; m++)
            {
                keyColumn[m, 0] = keyMatrix[m, 0];
            }

            string s1, s2, s3, xorResult;

            for (int n = 0; n < 4; n++)
            {
                for (int l = 0; l < 1; l++)
                {
                    s1 = getBin(keyColumn[n, l]);
                    s2 = getBin(columnMatrix[n, l]);
                    xorResult = XORR(s1, s2);

                    s3 = getBin(columnRcon[n, l]);
                    xorResult = XORR(xorResult, s3);

                    result[n, l] = getHex(xorResult);
                }
            }

            return result;
        }


        //a Function that takes the second column of the key and the first column of the key
        //and generates the second column 


        public static string[,] GetSecondColumn(string[,] secondCol, string[,] FirstCol)
        {


            //initializing the xor result and the first and second column strings

            string s1 = "", s2 = "", xor_result = "";

            //second column
            string[,] secondColumn = new string[4, 1];

            int i = 0;
            while (i < 4)
            {
                //looping to get the binary representation of the second column


                s1 = getBin(secondCol[i, 0]);


                s2 = getBin(FirstCol[i, 0]);

                xor_result = XORR(s1, s2);

                secondColumn[i, 0] = getHex(xor_result);
                i++;
            }




            return secondColumn;

        }

        // This function takes in two 2D string arrays, third_column_in_key and second_column_in_new_key,
        // and returns a new 2D string array called third_column with values obtained by performing
        // XOR operation on the binary values of the elements of third_column_in_key and second_column_in_new_key
        public static string[,] GetThirdColumn(string[,] third_column_in_key, string[,] second_column_in_new_key)
        {
            string[,] thirdCol = new string[4, 1]; // Creating an empty 2D string array of size 4x1

            string b1 = "", b2 = "", xorRes = ""; // Initializing string variables

            int i = 0; // Initializing loop counter

            // Converting the for loop to while loop
            while (i < 4)
            {
                b1 = getBin(third_column_in_key[i, 0]); // Converting the current element of third_column_in_key to binary
                b2 = getBin(second_column_in_new_key[i, 0]); // Converting the current element of second_column_in_new_key to binary

                xorRes = XORR(b1, b2); // Performing XOR operation on binary1 and binary2

                thirdCol[i, 0] = getHex(xorRes); // Converting the result of XOR operation to hexadecimal and storing it in third_column

                i++; // Incrementing the loop counter
            }

            return thirdCol; // Returning the 2D string array third_column
        }

        // This function takes in two 2D string arrays, fourth_column_in_key and third_column_in_new_key,
        // and returns a new 2D string array called fourth_column with values obtained by performing
        // XOR operation on the binary values of the elements of fourth_column_in_key and third_column_in_new_key
        public static string[,] GetFourthColumn(string[,] fourth_column_in_key, string[,] third_column_in_new_key)
        {
            string[,] fourth_column = new string[4, 1]; // Creating an empty 2D string array of size 4x1

            string binary1 = "", binary2 = "", xor_result = ""; // Initializing string variables

            int i = 0; // Initializing loop counter

            // Converting the while loop to for loop
            for (i = 0; i < 4; i++)
            {
                binary1 = getBin(fourth_column_in_key[i, 0]); // Converting the current element of fourth_column_in_key to binary
                binary2 = getBin(third_column_in_new_key[i, 0]); // Converting the current element of third_column_in_new_key to binary

                xor_result = XORR(binary1, binary2); // Performing XOR operation on binary1 and binary2

                fourth_column[i, 0] = getHex(xor_result); // Converting the result of XOR operation to hexadecimal and storing it in fourth_column
            }

            return fourth_column; // Returning the 2D string array fourth_column
        }


        public static string[,] getKeySchedule(string[,] key, int roundNum)
        {
            //storing the result in an empty 4x4 matrix

            string[,] res = new string[4, 4];


            //initializing the last column
            string[,] lastCol = new string[4, 1];

            int j = 0;



            //as
            while (j < 4) { lastCol[j, 0] = key[j, 3]; j++; }


            // Get first Column

            string[,] firstCol = new string[4, 1];

            firstCol = GetKeyScheduleFirstColumn(key, roundNum);

            int k = 0;

            while (k < 4)
            {
                res[k, 0] = firstCol[k, 0];
                k++;
            }

            //

            // Get rest

            // Get second column

            string[,] keySecondCol = new string[4, 1];
            for (int i = 0; i < 4; i++)
            {
                keySecondCol[i, 0] = key[i, 1];
            }

            string[,] newKeySecondCol = GetSecondColumn(keySecondCol, firstCol);

            for (int i = 0; i < 4; i++)
            {
                res[i, 1] = newKeySecondCol[i, 0];
            }

            // Get third column

            string[,] third_column_in_key = new string[4, 1];
            for (int i = 0; i < 4; i++)
            {
                third_column_in_key[i, 0] = key[i, 2];
            }

            string[,] third_column_in_new_key = GetThirdColumn(third_column_in_key, newKeySecondCol);

            for (int i = 0; i < 4; i++)
            {
                res[i, 2] = third_column_in_new_key[i, 0];
            }
            // Get fourth column

            string[,] fourth_column_in_new_key = GetFourthColumn(lastCol, third_column_in_new_key);

            for (int i = 0; i < 4; i++)
            {
                res[i, 3] = fourth_column_in_new_key[i, 0];
            }

            Console.WriteLine("The result matrix: ");
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    Console.Write(res[row, col] + "  ");
                }
                Console.WriteLine();
            }

            previous_key = res;

            return res;

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

                    round1key = getKeySchedule(previous_key, i);
                }
                else if (i == 1)
                {
                    round2key = getKeySchedule(previous_key, i);
                }
                else if (i == 2)
                {
                    round3key = getKeySchedule(previous_key, i);
                }
                else if (i == 3)
                {
                    round4key = getKeySchedule(previous_key, i);
                }
                else if (i == 4)
                {
                    round5key = getKeySchedule(previous_key, i);
                }
                else if (i == 5)
                {
                    round6key = getKeySchedule(previous_key, i);
                }
                else if (i == 6)
                {
                    round7key = getKeySchedule(previous_key, i);
                }
                else if (i == 7)
                {
                    round8key = getKeySchedule(previous_key, i);
                }
                else if (i == 8)
                {
                    round9key = getKeySchedule(previous_key, i);
                }
                else if (i == 9)
                {
                    round10key = getKeySchedule(previous_key, i);
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

                inverseMixColumns_result = MixColsInverse(AddRoundKey_result);

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