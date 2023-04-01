using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {

        public string DesEncrypt(string plainText, string key)
        {
            int[,] oneS;
            int[,] twoS;
            int[,] threeS;
            int[,] fourS;
            int[,] fiveS;
            int[,] sixS;
            int[,] sevenS;
            int[,] eightS;
            int[,] THe_ep;
            int[,] THe_ip;
            int[,] THE_p;
            int S__B;
            int RowS = 0;
            int ColomS = 0;
            string the_TMP_ofkey = "";
            string THe_E_BIT = "";
            string exork = "";
            List<string> THe_l = new List<string>();
            List<string> THe_r = new List<string>();
            List<string> THEkeys = new List<string>();
            string the_Lm = "";
            string the_rm = "";
            string r16l16;
            string str1 = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string str2 = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            List<string> THEc = new List<string>();
            List<string> THEd = new List<string>();
            oneS = new int[4, 16]
            {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
            };

            twoS = new int[4, 16]
            {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            };

            threeS = new int[4, 16]
            {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            };
            fourS = new int[4, 16]
            {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            };
            fiveS = new int[4, 16]
            {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            };
            sixS = new int[4, 16]
            {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            };
            sevenS = new int[4, 16]
            {
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            };
            eightS = new int[4, 16]
            {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            };
            THE_p = new int[8, 4]
            {
                { 16, 7, 20, 21 },
                { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 }
            };
            THe_ep = new int[8, 6]
           {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9 },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1 }
           };

            THe_ip = new int[8, 8]
            {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 }
            };

            int[,] one_IP = new int[8, 8]
            {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 }
            };

            int[,] onePC = new int[8, 7]
            {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 }
            };
            int[,] twoPC = new int[8, 6]
           {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 }
           };


            int num = str1.Length / 2;
            for (int i = 0; i < num; i++)
            {
                the_Lm = the_Lm + str1[i];
                the_rm = the_rm + str1[i + num];
            }
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    the_TMP_ofkey = the_TMP_ofkey + str2[onePC[i, j] - 1];
                }
            }
            string the_c = the_TMP_ofkey.Substring(0, 28);
            string the_d = the_TMP_ofkey.Substring(28, 28);

            for (int i = 0; i < 10; i++)
            {
            }

            string THE__TP = "";
            for (int i = 0; i < 17; i++)
            {
                THEc.Add(the_c);
                THEd.Add(the_d);
                THE__TP = "";
                if (i == 1 || i == 15 || i == 0 || i == 8)
                {
                    THE__TP = THE__TP + the_c[0];
                    the_c = the_c.Remove(0, 1);
                    the_c = the_c + THE__TP;
                    THE__TP = "";
                    THE__TP = THE__TP + the_d[0];
                    the_d = the_d.Remove(0, 1);
                    the_d = the_d + THE__TP;
                }
                else
                {
                    THE__TP = THE__TP + the_c.Substring(0, 2);
                    the_c = the_c.Remove(0, 2);
                    the_c = the_c + THE__TP;
                    THE__TP = "";
                    THE__TP = THE__TP + the_d.Substring(0, 2);
                    the_d = the_d.Remove(0, 2);
                    the_d = the_d + THE__TP;
                }
            }


            for (int i = 0; i < THEd.Count; i++)
            {
                THEkeys.Add(THEc[i] + THEd[i]);
            }


            List<string> THENumOfKeys = new List<string>();
            for (int k = 1; k < THEkeys.Count; k++)
            {
                the_TMP_ofkey = ""; THE__TP = ""; THE__TP = THEkeys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        the_TMP_ofkey = the_TMP_ofkey + THE__TP[twoPC[i, j] - 1];
                    }
                }

                THENumOfKeys.Add(the_TMP_ofkey);
            }
            string ip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip = ip + str1[THe_ip[i, j] - 1];
                }
            }

            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);

            THe_l.Add(l);
            THe_r.Add(r);
            string strX = "";
            string strH = "";
            List<string> S_box = new List<string>();
            string t = "";

            string tsb = "";
            string strb = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                THe_l.Add(r);
                exork = "";
                THe_E_BIT = "";
                lf = "";
                strb = "";
                S_box.Clear();
                tsb = "";
                ColomS = 0;
                RowS = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        THe_E_BIT = THe_E_BIT + r[THe_ep[j, k] - 1];
                    }
                }

                for (int g = 0; g < THe_E_BIT.Length; g++)
                {
                    exork = exork + (THENumOfKeys[i][g] ^ THe_E_BIT[g]).ToString();
                }

                for (int z = 0; z < exork.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exork.Length)
                            t = t + exork[y];
                    }

                    S_box.Add(t);
                }

                t = "";

                S__B = 0;
                for (int s = 0; s < S_box.Count; s++)
                {
                    t = S_box[s];
                    strX = t[0].ToString() + t[5];
                    strH = t[1].ToString() + t[2] + t[3] + t[4];

                    RowS = Convert.ToInt32(strX, 2);
                    ColomS = Convert.ToInt32(strH, 2);
                    if (s == 0) S__B = oneS[RowS, ColomS];
                    if (s == 1) S__B = twoS[RowS, ColomS];
                    if (s == 5) S__B = sixS[RowS, ColomS];
                    if (s == 6) S__B = sevenS[RowS, ColomS];
                    if (s == 7) S__B = eightS[RowS, ColomS];
                    if (s == 2) S__B = threeS[RowS, ColomS];
                    if (s == 3) S__B = fourS[RowS, ColomS];
                    if (s == 4) S__B = fiveS[RowS, ColomS];
                    tsb = tsb + Convert.ToString(S__B, 2).PadLeft(4, '0');
                }
                strX = ""; strH = "";

                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        strb = strb + tsb[THE_p[k, j] - 1];
                    }
                }

                for (int k = 0; k < strb.Length; k++)
                {
                    lf = lf + (strb[k] ^ l[k]).ToString();
                }

                r = lf;
                l = THe_l[i + 1];
                THe_r.Add(r);
            }


            r16l16 = THe_r[16] + THe_l[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + r16l16[one_IP[i, j] - 1];
                }
            }

            string x0 = "0x";
            string ct = x0 + Convert.ToInt64(ciphertxt, 2).ToString("X");

            return ct;
        }
        public string DesDecrypt(string cipherText, string key)
        {
            int[,] blainONE = new int[8, 7]
            {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 }
            };

            int[,] blainTWO = new int[8, 6]
            {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 }
            };

            int[,] oneS = new int[4, 16]
             {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
             };
            int[,] twoS = new int[4, 16]
            {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            };
            int[,] threeS = new int[4, 16]
            {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            };
            int[,] fourS = new int[4, 16]
            {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            };
            int[,] fiveS = new int[4, 16]
            {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            };
            int[,] sixS = new int[4, 16]
            {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            };
            int[,] sevenS = new int[4, 16]
            {
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            };
            int[,] eigthS = new int[4, 16]
            {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            };

            int[,] P = new int[8, 4]
            {
                { 16, 7, 20, 21 },
                { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 }
            };

            int[,] the_ep = new int[8, 6]
            {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9 },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1 }
            };

            int[,] theip = new int[8, 8]
            {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 }
            };

            int[,] theoneip = new int[8, 8]
            {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 }
            };


            string bicipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string bikey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string the_LM = "";
            string the_RM = "";

            for (int i = 0; i < bicipher.Length / 2; i++)
            {
                the_LM = the_LM + bicipher[i];
                the_RM = the_RM + bicipher[i + bicipher.Length / 2];
            }


            string tmp_key = "";
            List<string> the__c = new List<string>();
            List<string> the__d = new List<string>();

            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    tmp_key = tmp_key + bikey[blainONE[i, j] - 1];
                }
            }
            string RMVc = tmp_key.Substring(0, 28);
            string RMVd = tmp_key.Substring(28, 28);
            string Tp = "";
            for (int i = 0; i <= 16; i++)
            {
                the__c.Add(RMVc);
                the__d.Add(RMVd);
                Tp = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    Tp = Tp + RMVc[0];
                    RMVc = RMVc.Remove(0, 1);
                    RMVc = RMVc + Tp;
                    Tp = "";
                    Tp = Tp + RMVd[0];
                    RMVd = RMVd.Remove(0, 1);
                    RMVd = RMVd + Tp;
                }
                else
                {
                    Tp = Tp + RMVc.Substring(0, 2);
                    RMVc = RMVc.Remove(0, 2);
                    RMVc = RMVc + Tp;
                    Tp = "";
                    Tp = Tp + RMVd.Substring(0, 2);
                    RMVd = RMVd.Remove(0, 2);
                    RMVd = RMVd + Tp;
                }
            }

            List<string> keys = new List<string>();
            for (int i = 0; i < the__d.Count; i++)
            {
                keys.Add(the__c[i] + the__d[i]);
            }

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                tmp_key = "";
                Tp = "";
                Tp = keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        tmp_key = tmp_key + Tp[blainTWO[i, j] - 1];
                    }
                }

                nkeys.Add(tmp_key);
            }


            string ip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip = ip + bicipher[theip[i, j] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebit = "";
            string exork = "";
            List<string> sbox = new List<string>();

            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebit = ebit + r[the_ep[j, k] - 1];
                    }
                }

                for (int g = 0; g < ebit.Length; g++)
                {
                    exork = exork + (nkeys[nkeys.Count - 1 - i][g] ^ ebit[g]).ToString();
                }

                for (int z = 0; z < exork.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exork.Length)
                            t = t + exork[y];
                    }

                    sbox.Add(t);
                }

                t = "";
                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    if (s == 0) sb = oneS[row, col];
                    if (s == 1) sb = twoS[row, col];
                    if (s == 2) sb = threeS[row, col];
                    if (s == 3) sb = fourS[row, col];
                    if (s == 4) sb = fiveS[row, col];
                    if (s == 5) sb = sixS[row, col];
                    if (s == 6) sb = sevenS[row, col];
                    if (s == 7) sb = eigthS[row, col];
                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }
                x = ""; h = "";
                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                    }
                }
                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }
                r = lf;
                l = L[i + 1];
                R.Add(r);
            }
            string r16l16 = R[16] + L[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + r16l16[theoneip[i, j] - 1];
                }
            }
            string pt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
            return pt;
        }

        public string Decrypt(string cipherText, List<string> key)
        {
            string pt = "";

            pt = DesDecrypt(cipherText, key[1]);
            pt = DesEncrypt(pt, key[0]);
            pt = DesDecrypt(pt, key[1]);

            return pt;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string ct = "";

            ct = DesEncrypt(plainText, key[0]);
            ct = DesDecrypt(ct, key[1]);
            ct = DesEncrypt(ct, key[0]);

            return ct;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }

}
