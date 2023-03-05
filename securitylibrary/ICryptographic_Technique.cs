using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public interface ICryptographic_Technique<T, K>
    {
        /// <summary>
        /// This encrypts the given plain text with the given key.  
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <param name="key">The key.</param>
        /// <returns>The cipher text.</returns>
        T Encrypt(T plainText, K key);

        /// <summary>
        /// This decrypts the given cipher text with the given key.    
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <param name="key">The key.</param>
        /// <returns>The plain text.</returns>
        T Decrypt(T cipherText, K key);
    }
}
