using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int flag = 0;
            for (int key = 2; key < plainText.Length; key++)
            {
                string pT = plainText.ToUpper();

                var cTList = new List<StringBuilder>();
                StringBuilder result = new StringBuilder();

                int colNum = 0;
                while (colNum < key)
                {
                    StringBuilder buildCT = new StringBuilder();
                    cTList.Add(buildCT);
                    colNum++;
                }

                int currentLine = 0;

                int dir = 1;

                for (int y = 0; y < pT.Length; y++)
                {
                    cTList[currentLine].Append(pT[y]);

                    if (currentLine == 0)
                        dir++;

                    currentLine += 1;
                    if (currentLine == key)
                        currentLine = 0;
                }

                for (int z = 0; z < key; z++)
                {
                    string finalCT = cTList[z].ToString();
                    result.Append(finalCT);
                }
                string ctVal = result.ToString();
                if (ctVal == cipherText)
                {
                    flag = key;
                    break;
                }
            }
            return flag;
        }


        public string Decrypt(string cipherText, int key)
        {
            int ctLen = cipherText.Length;

            double ct = (double)(ctLen);
            ct /= (double)(key);
            int arrLen = (int)Math.Ceiling((ct));

            char[,] pTRec;
            pTRec = new char[key, arrLen];
            int rowNum = 0;
            int x = 0;
            while (rowNum < key)
            {
                for (int i = 0; i < arrLen; i++)
                {
                    if (x != ctLen)
                    {
                        pTRec[rowNum, i] = cipherText[x];
                        x++;
                    }

                }
                rowNum++;
            }
            string resultPT = "";
            int lenCT = 0;
            while (lenCT < arrLen)
            {
                for (int k = 0; k < key; k++)
                {
                    resultPT += pTRec[k, lenCT];
                }
                lenCT++;
            }
            return resultPT;
        }

        public string Encrypt(string plainText, int key)
        {

            int ptLen = plainText.Length;
            char[,] cTbuild;
            cTbuild = new char[key, ptLen];
            int colNum = 0;
            int x = 0;
            while (colNum < ptLen)
            {
                for (int i = 0; i < key; i++)
                {
                    if (x != ptLen)
                    {
                        cTbuild[i, colNum] = plainText[x];
                        x++;
                    }

                }
                colNum++;
            }
            string resultCT = "";
            int len = 0;
            while (len < key)
            {
                for (int k = 0; k < ptLen; k++)
                {
                    if (cTbuild[len, k] != '0')
                    {
                        resultCT += cTbuild[len, k];
                    }
                }
                len++;
            }
            return resultCT;
        }
    }
}

