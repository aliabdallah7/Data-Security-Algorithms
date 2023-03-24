using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        //Calculate the modular inverse of the determinant
        public int ModInverse(int a)
        {
            a = a % 26;
            if (a < 0)
                a += 26;
            for (int x = 1; x < 26; x++)
                if ((a * x) % 26 == 1)
                    return x;
            return 0;
        }
        // Calculate the inverse matrix
        public List<int> inverseMatrix(List<int> adj, int det, int size)
        {
            for (int i = 0; i < size; i++)
            {
                adj[i] = (adj[i] * det) % 26;
                if (adj[i] < 0)
                    adj[i] += 26;
            }
            return adj;
        }
        // Calculate the adjoint 3x3 matrix
        public void adjointMatrix(List<int> adj, List<int> key)
        {
            adj.Add((key[4] * key[8] - key[5] * key[7]) % 26);
            adj.Add((-key[1] * key[8] + key[2] * key[7]) % 26);
            adj.Add((key[1] * key[5] - key[2] * key[4]) % 26);
            adj.Add((-key[3] * key[8] + key[5] * key[6]) % 26);
            adj.Add((key[0] * key[8] - key[2] * key[6]) % 26);
            adj.Add((-key[0] * key[5] + key[2] * key[3]) % 26);
            adj.Add((key[3] * key[7] - key[4] * key[6]) % 26);
            adj.Add((-key[0] * key[7] + key[1] * key[6]) % 26);
            adj.Add((key[0] * key[4] - key[1] * key[3]) % 26);
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //  throw new NotImplementedException();
            List<int> Key = new List<int>();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            Key.Add(i);
                            Key.Add(j);
                            Key.Add(k);
                            Key.Add(l);
                            List<int> testkey = Encrypt(plainText, Key);
                            if (testkey.SequenceEqual(cipherText))
                            { return Key; }
                            Key.Clear();
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();
            List<int> adj = new List<int>();
            int det;
            if (key.Count % 2 == 0)
            {
                det = ModInverse(key[0] * key[3] - key[1] * key[2]);
                if (det == 0)
                    throw new System.Exception();
                // Calculate the adjoint matrix
                adj.Add(key[3]);
                adj.Add(-key[1]);
                adj.Add(-key[2]);
                adj.Add(key[0]);
                adj = inverseMatrix(adj, det, 4);
                // Decrypt the cipher text
                for (int i = 0; i < cipherText.Count; i += 2)
                {
                    int x = cipherText[i];
                    int y = cipherText[i + 1];
                    int plainX = (adj[0] * (x) + adj[1] * (y)) % 26;
                    int plainY = (adj[2] * (x) + adj[3] * (y)) % 26;
                    if (plainX < 0)
                        plainX += 26;
                    if (plainY < 0)
                        plainY += 26;
                    plainText.Add((plainX));
                    plainText.Add((plainY));
                }
            }
            else
            {
                det = ModInverse(key[0] * (key[4] * key[8] - key[5] * key[7]) -
                      key[1] * (key[3] * key[8] - key[5] * key[6]) +
                      key[2] * (key[3] * key[7] - key[4] * key[6])) % 26;

                if (det == 0 || ModInverse(det) == 0)
                    throw new System.Exception("Invalid key: determinant must be nonzero and invertible mod 26");
                // Calculate the adjoint matrix
                adjointMatrix(adj, key);
                adj = inverseMatrix(adj, det, 9);

                // Decrypt the cipher text
                for (int i = 0; i < cipherText.Count; i += 3)
                {
                    int x = cipherText[i];
                    int y = cipherText[i + 1];
                    int z = cipherText[i + 2];
                    int plainX = (adj[0] * (x) + adj[1] * (y) + adj[2] * (z)) % 26;
                    int plainY = (adj[3] * (x) + adj[4] * (y) + adj[5] * (z)) % 26;
                    int plainZ = (adj[6] * (x) + adj[7] * (y) + adj[8] * (z)) % 26;
                    if (plainX < 0)
                        plainX += 26;
                    if (plainY < 0)
                        plainY += 26;
                    if (plainZ < 0)
                        plainZ += 26;
                    plainText.Add((plainX));
                    plainText.Add((plainY));
                    plainText.Add((plainZ));
                }
            }
            return plainText;
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //  throw new NotImplementedException();
            List<int> cipherText = new List<int>();
            // check if the key matrix is 2x2 or 3x3
            if (key.Count() % 2 == 0) // key is 2x2
            {
                for (int i = 0; i < plainText.Count(); i += 2)
                {
                    for (int j = 0; j < key.Count(); j += 2)
                        cipherText.Add(((plainText[i] * key[j]) + (plainText[i + 1] * key[j + 1])) % 26);
                }
            }
            else  // key is 3x3
            {
                for (int i = 0; i < plainText.Count(); i += 3)
                {
                    for (int j = 0; j < key.Count(); j += 3)
                        cipherText.Add(((plainText[i] * key[j]) + (plainText[i + 1] * key[j + 1]) + (plainText[i + 2] * key[j + 2])) % 26);
                }
            }
            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //  throw new NotImplementedException();
            List<int> key = new List<int>();
            // [1] get inverse of the plaintext
            int det = (plain3[0] * (plain3[4] * plain3[8] - plain3[5] * plain3[7]) -
                      plain3[1] * (plain3[3] * plain3[8] - plain3[5] * plain3[6]) +
                      plain3[2] * (plain3[3] * plain3[7] - plain3[4] * plain3[6])) % 26;
            if (det == 0 || ModInverse(det) == 0)
                throw new System.Exception("Invalid key: determinant must be nonzero and invertible mod 26");
            // Calculate the adjoint matrix
            List<int> adj = new List<int>();
            adjointMatrix(adj, plain3);
            det = ModInverse(det);
            adj = inverseMatrix(adj, det, 9);
            //[2] key = (c.p * inverse of p.t )%26
            key.Add((adj[0] * cipher3[0] + (adj[1] * cipher3[3]) + (adj[2] * cipher3[6])) % 26);
            key.Add((adj[3] * cipher3[0] + (adj[4] * cipher3[3]) + (adj[5] * cipher3[6])) % 26);
            key.Add((adj[6] * cipher3[0] + (adj[7] * cipher3[3]) + (adj[8] * cipher3[6])) % 26);
            key.Add((adj[0] * cipher3[1] + (adj[1] * cipher3[4]) + (adj[2] * cipher3[7])) % 26);
            key.Add((adj[3] * cipher3[1] + (adj[4] * cipher3[4]) + (adj[5] * cipher3[7])) % 26);
            key.Add((adj[6] * cipher3[1] + (adj[7] * cipher3[4]) + (adj[8] * cipher3[7])) % 26);
            key.Add((adj[0] * cipher3[2] + (adj[1] * cipher3[5]) + (adj[2] * cipher3[8])) % 26);
            key.Add((adj[3] * cipher3[2] + (adj[4] * cipher3[5]) + (adj[5] * cipher3[8])) % 26);
            key.Add((adj[6] * cipher3[2] + (adj[7] * cipher3[5]) + (adj[8] * cipher3[8])) % 26);
            return key;
        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
