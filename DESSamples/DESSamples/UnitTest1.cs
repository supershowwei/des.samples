using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DESSamples
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void Test_DES_Encrypt()
        {
            string source = "ABC";

            var encryptedString = this.EncryptByDES(source, "helloworld", "worldhello");
            var decryptedString = this.DecryptByDES(encryptedString, "helloworld", "worldhello");

            Assert.AreEqual(source, decryptedString);
        }

        private byte[] HashByMD5(string source)
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();

            return md5.ComputeHash(Encoding.UTF8.GetBytes(source));
        }

        private string EncryptByDES(string source, string key, string iv)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();

            // Rfc2898DeriveBytes 類別可以用來從基底金鑰與其他參數中產生衍生金鑰。
            // 使用 MD5 來 Hash 出 Rfc2898 需要的 Salt。
            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(key, this.HashByMD5(key));

            // 8 bits = 1 byte，將 KeySize 及 BlockSize 個別除以 8，取得 Rfc2898 產生衍生金鑰的長度。
            des.Key = rfc2898.GetBytes(des.KeySize / 8);
            des.IV = rfc2898.GetBytes(des.BlockSize / 8);

            var dateByteArray = Encoding.UTF8.GetBytes(source);

            // 加密
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(dateByteArray, 0, dateByteArray.Length);
                cs.FlushFinalBlock();

                return Convert.ToBase64String(ms.ToArray());
            }
        }

        private string DecryptByDES(string encrypted, string key, string iv)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();

            // Rfc2898DeriveBytes 類別可以用來從基底金鑰與其他參數中產生衍生金鑰。
            // 使用 MD5 來 Hash 出 Rfc2898 需要的 Salt。
            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(key, this.HashByMD5(key));

            // 8 bits = 1 byte，將 KeySize 及 BlockSize 個別除以 8，取得 Rfc2898 產生衍生金鑰的長度。
            des.Key = rfc2898.GetBytes(des.KeySize / 8);
            des.IV = rfc2898.GetBytes(des.BlockSize / 8);

            var dateByteArray = Convert.FromBase64String(encrypted);

            // 解密
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(dateByteArray, 0, dateByteArray.Length);
                cs.FlushFinalBlock();

                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
    }
}
