using System;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
       string[] toBin =
        {
            "0000","0001","0010","0011","0100","0101","0110","0111",
            "1000","1001","1010","1011","1100","1101","1110","1111"
        };
        int[] LeftShifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        int[] PC1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        int[] PC2 =
      {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };
        int[] IP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        int[] ExpansionMat =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };
        int[] P =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };
        int[] IPinverse =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };
        int[,] SBoxes =
        {
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };


        char apli_xop(char x, char y)
        {
            if ((x == '0' && y == '1') || (x == '1' && y == '0'))
            {
                return '1';
            }
            else
            {
                return '0';
            }
        }

        int toInt2(string input)
        {
            switch (input)
            {
                case "00":
                    return 0;
                    break;
                case "01":
                    return 1;
                    break;
                case "10":
                    return 2;
                    break;
                default:
                    return 3;
                    break;
            }
        }

        int toInt4(string input)
        {
            switch (input)
            {
                case "0000":
                    return 0;
                    break;
                case "0001":
                    return 1;
                    break;
                case "0010":
                    return 2;
                    break;
                case "0011":
                    return 3;
                    break;
                case "0100":
                    return 4;
                    break;
                case "0101":
                    return 5;
                    break;
                case "0110":
                    return 6;
                    break;
                case "0111":
                    return 7;
                    break;
                case "1000":
                    return 8;
                    break;
                case "1001":
                    return 9;
                    break;
                case "1010":
                    return 10;
                    break;
                case "1011":
                    return 11;
                    break;
                case "1100":
                    return 12;
                    break;
                case "1101":
                    return 13;
                    break;
                case "1110":
                    return 14;
                    break;
                default:
                    return 15;
                    break;
            }

        }

        char toHEX(string input)
        {
            switch(input)
            {
                case "0000":
                    return '0';
                    break;
                case "0001":
                    return '1';
                    break;
                case "0010":
                    return '2';
                    break;
                case "0011":
                    return '3';
                    break;
                case "0100":
                    return '4';
                    break;
                case "0101":
                    return '5';
                    break;
                case "0110":
                    return '6';
                    break;
                case "0111":
                    return '7';
                    break;
                case "1000":
                    return '8';
                    break;
                case "1001":
                    return '9';
                    break;
                case "1010":
                    return 'A';
                    break;
                case "1011":
                    return 'B';
                    break;
                case "1100":
                    return 'C';
                    break;
                case "1101":
                    return 'D';
                    break;
                case "1110":
                    return 'E';
                    break;
                default:
                    return 'F';
                    break;
            }
        }



        public override string Encrypt(string plainText, string key)
        {
            string cipherText = String.Empty;
            int q = 2;

            int r = 0;

            int u = 0;
            StringBuilder expandedR;
            StringBuilder apli_xopOutput;
            StringBuilder sboxOutput;
            StringBuilder permutationOutput;
            string Bn;
            int row;
            int column;
            int t = 2;
            int y = 0;
            int a = 1;
            //convert key to string of 1's and 0's
            StringBuilder binaryKey = new StringBuilder();
            int w = 0;//
            int e = 0;
            while (q < key.Length)
            {
                binaryKey.Append(toBin[int.Parse(key[q].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                q++;
            }

            // apply PC1
            StringBuilder PC1key = new StringBuilder();

            while (w < PC1.Length)
            {
                PC1key.Append(binaryKey[PC1[w] - 1]);
                w++;
            }

            //calculate Cn and Dn 
            string[] C = new string[17];
            string[] D = new string[17];

            C[0] = PC1key.ToString().Substring(0, 28);
            D[0] = PC1key.ToString().Substring(28, 28);

            string shifted_C = C[0];
            string shifted_D = D[0];
            char rightMost;

            while (e < 16)
            {
                int j = 0;
                while ( j < LeftShifts[e])
                {
                    rightMost = shifted_C[0];
                    shifted_C = shifted_C.Remove(0, 1);
                    shifted_C += rightMost;

                    rightMost = shifted_D[0];
                    shifted_D = shifted_D.Remove(0, 1);
                    shifted_D += rightMost;
                    j++;
                }
                C[e + 1] = shifted_C;
                D[e + 1] = shifted_D;
                e++;
            }

            //calculate Kn
            string[] K = new string[16];

            int len = K.Length;
            while (r < len)
            {
                K[r] = C[r + 1] + D[r + 1];
                r++;
            }

            //apply PC2
            StringBuilder[] roundKey = new StringBuilder[16];
            int i = 0;
            while (i < len)
            {
                roundKey[i] = new StringBuilder();
                for (int j = 0; j < PC2.Length; j++)
                {
                    roundKey[i].Append(K[i][PC2[j] - 1]);
                }
                i++;
            }

            //start encrypting plain text

            //conver palint text to array of 0's and 1's
            StringBuilder binaryPlainText = new StringBuilder();

            while (t < key.Length)
            {
                binaryPlainText.Append(toBin[int.Parse(plainText[t].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                t++;
            }//here5

            //apply initial permutation
            StringBuilder initialPermutation = new StringBuilder();

            while (y < IP.Length)
            {
                initialPermutation.Append(binaryPlainText[IP[y] - 1]);
                y++;
            }

            //calculate Ln and Rn
            string[] L = new string[17];
            string[] R = new string[17];

            L[0] = initialPermutation.ToString().Substring(0, 32);
            R[0] = initialPermutation.ToString().Substring(32, 32);


            //repeat process for 16 round

            while (a < 17)//here
            {
                L[a] = R[a - 1];
                expandedR = new StringBuilder();
                apli_xopOutput = new StringBuilder();
                sboxOutput = new StringBuilder();
                permutationOutput = new StringBuilder();
                //expand R
                for (int jj = 0; jj < ExpansionMat.Length; jj++)//here1
                {
                    expandedR.Append(R[a - 1][ExpansionMat[jj] - 1]);
                }
                // E(Ri) apli_xop Ki
                for (int jj = 0; jj < expandedR.Length; jj++)//here1
                {
                    apli_xopOutput.Append(apli_xop(expandedR[jj], roundKey[a - 1][jj]));
                }
                // apply sbox
                int j = 0;
                while (j < 8 )//here1
                {
                    Bn = apli_xopOutput.ToString().Substring(6 * j, 6);
                    row = toInt2(Bn[0] + string.Empty + Bn[5]);
                    column = toInt4(Bn.Substring(1, 4));
                    sboxOutput.Append(toBin[SBoxes[j, (row * 16) + column]]);
                    j++;
                }
                //apply permutation
                for (int z = 0; z < P.Length; z++)//here1
                {
                    permutationOutput.Append(sboxOutput[P[z] - 1]);
                }
                //calculate Ri
                apli_xopOutput = new StringBuilder();
                for (int jj = 0; jj < permutationOutput.Length; jj++)//here1
                {
                    apli_xopOutput.Append(apli_xop(L[a - 1][jj], permutationOutput[jj]));
                }
                R[a] = apli_xopOutput.ToString();
                a++;
            }

            string R16L16 = R[16] + L[16];
            StringBuilder binaryCipherText = new StringBuilder();
            //apply p^-1
            for (int p = 0; p < IPinverse.Length; p++)//here1
            {
                binaryCipherText.Append(R16L16[IPinverse[p] - 1]);
            }

            //conver output to HEX
            cipherText += "0x";

            while (u < 16)
            {
                cipherText += toHEX(binaryCipherText.ToString().Substring(4 * u, 4));
                u++;
            }
            return cipherText;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string plainText = String.Empty;


            //convert key to string of 1's and 0's
            StringBuilder binaryKey = new StringBuilder();
            
            for (int i = 2; i < key.Length; i++)
            {
                binaryKey.Append(toBin[int.Parse(key[i].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }

            // apply PC_1
            StringBuilder pc_1 = new StringBuilder();
            int s = 0;
            while (s < this.PC1.Length)
            {
                pc_1.Append(binaryKey[this.PC1[s] - 1]);
                s++;
            }

            //How to calculate   CN and DN 

            string[] c_n = new string[17];
            string[] d_n = new string[17];

            c_n[0] = pc_1.ToString().Substring(0, 28);
            d_n[0] = pc_1.ToString().Substring(28, 28);

            string shifted_C = c_n[0];
            string shifted_D = d_n[0];
            char rightMost;
            int s1 = 0;
            while (s1 < 16)
            {
                int s2 = 0;
                while (s2 < LeftShifts[s1])
                {
                    rightMost = shifted_C[0];
                    shifted_C = shifted_C.Remove(0, 1);
                    shifted_C += rightMost;

                    rightMost = shifted_D[0];
                    shifted_D = shifted_D.Remove(0, 1);
                    shifted_D += rightMost;
                    s2++;
                }
                c_n[s1 + 1] = shifted_C;
                d_n[s1 + 1] = shifted_D;
                s1++;
            }

            //calculate Kn
            string[] K = new string[16];
            
            for (int temp = 0; temp < K.Length; temp++)
            {
                K[temp] = c_n[temp + 1] + d_n[temp + 1];
                
            }

            //How to find pc2 &apply pc2

            StringBuilder[] roundKey = new StringBuilder[16];
            int q1 = 0;
            while (q1 < K.Length)
            {
                roundKey[q1] = new StringBuilder();
                int q2 = 0;
                while (q2 < PC2.Length)
                {
                    roundKey[q1].Append(K[q1][PC2[q2] - 1]);
                    q2++;
                }
                q1++;
            }

            // decrypting 

            //convert palint text to the opposite (0's & 1's)
            StringBuilder binaryCipherText = new StringBuilder();
            int re = 2;
            while (re < key.Length)
            {
                binaryCipherText.Append(toBin[int.Parse(cipherText[re].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                re++;
            }

            //apply the permutation



            StringBuilder initialPermutation = new StringBuilder();
            int se = 0;
            while (se < IP.Length)
            {
                initialPermutation.Append(binaryCipherText[IP[se] - 1]);
                se++;
            }

            //calculate Ln and Rn
            string[] L = new string[17];
            string[] R = new string[17];

            L[0] = initialPermutation.ToString().Substring(0, 32);
            R[0] = initialPermutation.ToString().Substring(32, 32);

            StringBuilder expandedR;
            StringBuilder xor;
            StringBuilder sbox;
            StringBuilder permutation;
            string Bn;
            int row;
            int column;

            //repeat process for 16 round
            for (int rep = 1; rep < 17; rep++)
            {
                L[rep] = R[rep - 1];
                expandedR = new StringBuilder();

                xor = new StringBuilder();

                permutation = new StringBuilder();

                sbox = new StringBuilder();


                //expand R
                for (int fi = 0; fi < ExpansionMat.Length; fi++)
                {
                    expandedR.Append(R[rep - 1][ExpansionMat[fi] - 1]);
                }
                // Ri xor with Ki
                for (int RI1 = 0; RI1 < expandedR.Length; RI1++)
                {
                    xor.Append(apli_xop(expandedR[RI1], roundKey[15 - (rep - 1)][RI1]));
                }
                // applying sbox
                for (int S1 = 0; S1 < 8; S1++)
                {
                    Bn = xor.ToString().Substring(6 * S1, 6);
                    row = toInt2(Bn[0] + string.Empty + Bn[5]);
                    column = toInt4(Bn.Substring(1, 4));
                    sbox.Append(toBin[SBoxes[S1, (row * 16) + column]]);
                }
                //applying permutation
                for (int per1 = 0; per1 < P.Length; per1++)
                {
                    permutation.Append(sbox[P[per1] - 1]);
                }
                //How calculate Ri
                xor = new StringBuilder();
                int permLen = permutation.Length;
                for (int RI1 = 0; RI1 < permLen; RI1++)
                {
                    xor.Append(apli_xop(L[rep - 1][RI1], permutation[RI1]));
                }
                R[rep] = xor.ToString();
            }

            string R_L_Sixteen = R[16] + L[16];
            StringBuilder binaryPlainText = new StringBuilder();
            //apply p^-1
            int lennIP = IPinverse.Length;
            for (int p_Minus = 0; p_Minus < lennIP; p_Minus++)
            {
                binaryPlainText.Append(R_L_Sixteen[IPinverse[p_Minus] - 1]);
                
            }

            //conver output to HEX
            plainText += "0x";
            int ou = 0;
            while (ou < 16)
            {
                plainText += toHEX(binaryPlainText.ToString().Substring(4 * ou, 4));
                ou++;
            }
            return plainText;
        }
    }
}