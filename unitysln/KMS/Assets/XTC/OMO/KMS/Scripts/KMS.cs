using System;
using System.Text;
using System.Security.Cryptography;

namespace XTC.OMO.SDK.KMS
{
    public class License
    {
        public static string exception {get; private set;}
        public static int Verify(string[] _lines, string _appKey, string _appSecret, string _deviceCode)
        {
            return verify(_lines, _appKey, _appSecret, _deviceCode);
        }

        private static int verify(string[] _lines, string _appKey, string _appSecret, string _deviceCode)
        {
            string[] lines = _lines;
            if (lines.Length < 14)
            {
                return 1;
            }
            if ("key:" != lines[0] ||
                "code:" != lines[2] ||
                "timestamp:" != lines[4] ||
                "expiry:" != lines[6] ||
                "storage:" != lines[8] ||
                "cer:" != lines[10] ||
                "sig:" != lines[12])
            {
                return 2;
            }

            byte[] password = toPassword(_appKey, _appSecret);
            string payload = string.Format("key:\n{0}\ncode:\n{1}\ntimestamp:\n{2}\nexpiry:\n{3}\nstorage:\n{4}\ncer:\n{5}",
                _appKey, _deviceCode, lines[5], lines[7], lines[9], lines[11]);

            byte[] identity_ciphertext = aesEncrypt(Encoding.UTF8.GetBytes(payload), password);
            byte[] identity = toMD5(identity_ciphertext);

            //take cer
            byte[] pubkey_ciphertext;
            try
            {
                pubkey_ciphertext = decodeBase64(lines[11]);
            }
            catch (System.Exception ex)
            {
                exception = ex.Message;
                return 3;
            }

            byte[] pubkey;
            try
            {
                pubkey = aesDecrypt(pubkey_ciphertext, password);
            }
            catch (System.Exception ex)
            {
                exception = ex.Message;
                return 4;
            }

            //take sig
            byte[] sig_ciphertext;
            try
            {
                sig_ciphertext = decodeBase64(lines[13]);
            }
            catch (System.Exception ex)
            {
                exception = ex.Message;
                return 5;
            }

            bool pass;
            try
            {
                pass = rsaVerify(pubkey, identity, sig_ciphertext);
            }
            catch (System.Exception ex)
            {
                exception = ex.Message;
                return 6;
            }

            if (!pass)
            {
                return 6;
            }

            long timestamp;
            if (!long.TryParse(lines[5], out timestamp))
            {
                return 7;
            }

            int expiry;
            if (!int.TryParse(lines[7], out expiry))
            {
                return 8;
            }

            if (expiry != 0)
            {
                TimeSpan ts = System.DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0);
                long now = Convert.ToInt64(ts.TotalSeconds);
                if (now - timestamp > expiry * 24 * 60 * 60)
                {
                    return 14;
                }
            }

            return 0;
        }

        private static byte[] toMD5(string _value)
        {
            return toMD5(Encoding.UTF8.GetBytes(_value));
        }

        private static byte[] toMD5(byte[] _value)
        {
            MD5CryptoServiceProvider md5Hasher = new MD5CryptoServiceProvider();
            byte[] bytes = md5Hasher.ComputeHash(_value);
            StringBuilder tmp = new StringBuilder();
            foreach (byte i in bytes)
            {
                tmp.Append(i.ToString("x2"));
            }
            return Encoding.UTF8.GetBytes(tmp.ToString());
        }

        private static byte[] toPassword(string _appkey, string _appSecret)
        {
            byte[] pwd = toMD5(_appkey + "*!@#omo#@!*" + _appSecret);
            string value = Encoding.UTF8.GetString(pwd).ToUpper();
            return Encoding.UTF8.GetBytes(value);
        }

        private static byte[] aesEncrypt(byte[] _data, byte[] _password)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;
            rijndaelCipher.KeySize = 128;
            rijndaelCipher.BlockSize = 128;
            byte[] iv = new byte[16];
            Array.Copy(_password, iv, 16);
            rijndaelCipher.Key = _password;
            rijndaelCipher.IV = iv;
            ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            return transform.TransformFinalBlock(_data, 0, _data.Length);
        }

        private static byte[] aesDecrypt(byte[] _data, byte[] _password)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;
            rijndaelCipher.KeySize = 128;
            rijndaelCipher.BlockSize = 128;
            byte[] iv = new byte[16];
            Array.Copy(_password, iv, 16);
            rijndaelCipher.Key = _password;
            rijndaelCipher.IV = iv;
            ICryptoTransform transform = rijndaelCipher.CreateDecryptor();
            return transform.TransformFinalBlock(_data, 0, _data.Length);
        }

        // PKCS1v15
        private static bool rsaVerify(byte[] _publickKey, byte[] _data, byte[] _sign)
        {
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(_data);

            RSAParameters rsaParameters = fromPemPublicKey(_publickKey);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            return rsaDeformatter.VerifySignature(hash, _sign);
        }


        private static byte[] decodeBase64(string _value)
        {
            string value = _value.Replace("-", "+").Replace("_", "/");
            return Convert.FromBase64String(value);
        }

        internal static RSAParameters fromPemPublicKey(byte[] _publickKey)
        {
            string pemPubKey = Encoding.UTF8.GetString(_publickKey);
            pemPubKey = pemPubKey.Replace("-----BEGIN RSA PUBLIC KEY-----", "").Replace("-----END RSA PUBLIC KEY-----", "").Replace("\n", "").Replace("\r", "");
            var keyData = Convert.FromBase64String(pemPubKey);
            var keySize1024 = (keyData.Length == 162);
            var keySize2048 = (keyData.Length == 294);
            if (!(keySize1024 || keySize2048))
            {
                throw new ArgumentException("pem file content is incorrect, Only support the key size is 1024 or 2048");
            }

            var pemModulus = (keySize1024 ? new byte[128] : new byte[256]);
            var pemPublicExponent = new byte[3];
            Array.Copy(keyData, (keySize1024 ? 29 : 33), pemModulus, 0, (keySize1024 ? 128 : 256));
            Array.Copy(keyData, (keySize1024 ? 159 : 291), pemPublicExponent, 0, 3);
            var para = new RSAParameters { Modulus = pemModulus, Exponent = pemPublicExponent };
            return para;
        }
    }//class
}//namespace
