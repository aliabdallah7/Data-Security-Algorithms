using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private static string[] SBOX = {
            "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
            "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
            "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
            "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
            "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
            "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
            "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
            "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
            "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
            "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
            "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
            "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
            "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
            "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
            "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
            "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"
        };

        public string HexToBin(string x)
        {
            x = Convert.ToString(Convert.ToInt64(x, 16), 2);
            x = x.Length < 8 ? (new String('0', 8 - x.Length) + x) : x;
            return x;
        }
        public string addRoundKey(string a, string b)
        {
            string res = "";
            for (int i = 0; i < a.Length; i++)
            {
                res += a[i] == b[i] ? '0' : '1';
            }

            return res;
        }
        public string binToHex(string a, int b)
        {
            string aR = a[b].ToString() + a[b + 1].ToString() + a[b + 2].ToString() + a[b + 3].ToString();
            aR = Convert.ToInt32(aR, 2).ToString();
            aR = aR.Length == 1 ? aR :
                aR == "10" ? "A" :
                aR == "11" ? "B" :
                aR == "12" ? "C" :
                aR == "13" ? "D" :
                aR == "14" ? "E" : "F";
            return aR;
        }



        public string[] mixColumnMatrix = {
        "02", "03", "01", "01",
        "01", "02", "03", "01",
        "01", "01", "02", "03",
        "03", "01", "01", "02"
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


        private string[] substituteBytes(string[] array, string[] sbox)
        {
            for (int i = 0; i < 4; i++)
            {
                string temp = array[i];
                int row = (int)Convert.ToInt32(temp[0].ToString(), 16);
                int col = (int)Convert.ToInt32(temp[1].ToString(), 16);
                array[i] = sbox[row];
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
                    column1 = substituteBytes(column1, SBOX);

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

        public int whereMySBox(string a)
        {
            int aR = Convert.ToInt32(a[0].ToString(), 16);
            int aL = Convert.ToInt32(a[1].ToString(), 16);
            int res = aR * 16 + aL;
            //Console.WriteLine(res.ToString() + ' ');
            return res;
        }
        private int[,] MixColumns(int[,] s)
        {
            for (var c = 0; c < 4; c++)
            {
                var a = new int[4];  // 'a' is a copy of the current column from 's'
                var b = new int[4];  // 'b' is a•{02} in GF(2^8)
                for (var i = 0; i < 4; i++)
                {
                    a[i] = s[i, c];
                    b[i] = (s[i, c] & 0x80) != 0 ? ((s[i, c] << 1) ^ 0x011b) : (s[i, c] << 1);
                }
                // a[n] ^ b[n] is a•{03} in GF(2^8)
                s[0, c] = (b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]); // 2*a0 + 3*a1 + a2 + a3
                s[1, c] = (a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]); // a0 * 2*a1 + 3*a2 + a3
                s[2, c] = (a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]); // a0 + a1 + 2*a2 + 3*a3
                s[3, c] = (a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]); // 3*a0 + a1 + a2 + 2*a3
            }
            return s;
        }


        public List<string> twoCharsMatrix(string x)
        {
            List<string> strList = new List<string>();
            string str = x.Split('x')[1];
            for (int i = 0; i < str.Length; i+=2)
            {
                strList.Add(str[i].ToString()+str[i+1].ToString());
            }
            
            return strList;
        }




        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }
        public override string Encrypt(string plainText, string key)
        {
            // Divide the plaintext and key into 2-characters matrices
            List<string> PT = twoCharsMatrix(plainText);
            List<string> KT = twoCharsMatrix(key);

            // Convert the matrices to binary
            List<string> PTBinary = PT.Select(HexToBin).ToList();
            List<string> KTBinary = KT.Select(HexToBin).ToList();

            // Apply Add Round Key
            List<string> stateRounded = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                stateRounded.Add(addRoundKey(KTBinary[i], PTBinary[i]));
            }

            // Apply S-box substitution
            List<string> sBoxMatrixChanger = stateRounded.Select(whereMySBox).Select(s => SBOX[s]).ToList();

            // Apply Shift Rows
            List<string> Shifted = new List<string>(16);
            for (int i = 0; i < 16; i++)
            {
                Shifted.Add("");
            }
            // Apply Shift Rows
            List<List<string>> state = new List<List<string>>();
            for (int i = 0; i < 4; i++)
            {
                state.Add(new List<string>());
                for (int j = 0; j < 4; j++)
                {
                    state[i].Add(sBoxMatrixChanger[i * 4 + j]);
                }
            }

            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    state[i].Insert(0, state[i].Last());
                    state[i].RemoveAt(4);
                }
            }

            // Flatten the state matrix into a single list
            List<string> shifted = state.SelectMany(row => row).ToList();


            for (int i = 0; i < 16; i++)
            {
                if (i % 4 == 0)
                {
                    Shifted[i] = sBoxMatrixChanger[i];
                }
                else if (i == 5 || i == 9 || i == 13)
                {
                    Shifted[i - 4] = sBoxMatrixChanger[i];
                }
                else if (i == 3 || i == 7 || i == 11)
                {
                    Shifted[i + 4] = sBoxMatrixChanger[i];
                }
                else if (i == 10 || i == 14)
                {
                    Shifted[i - 8] = sBoxMatrixChanger[i];
                }
                else if (i == 2 || i == 6)
                {
                    Shifted[i + 8] = sBoxMatrixChanger[i];
                }
                else if (i == 15)
                {
                    Shifted[i - 12] = sBoxMatrixChanger[i];
                }
                else if (i == 1)
                {
                    Shifted[i + 12] = sBoxMatrixChanger[i];
                }
            }

            // Apply Mix Columns
            int[,] stateMixed = new int[4, 4];
            for (int c = 0; c < 4; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    stateMixed[r, c] = Convert.ToInt32(Shifted[c * 4 + r], 16);
                }
            }
            int[,] mixedColumns = MixColumns(stateMixed);

            // Convert the mixed state matrix back to a list of hex strings
            List<string> mixed = new List<string>();
            for (int c = 0; c < 4; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    mixed.Add(mixedColumns[r, c].ToString("X2"));
                }
            }

            // Combine the matrix back into a single string and return it
            return string.Join("", mixed);
        }

    }
}