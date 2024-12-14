using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class Aes
    {
        private int[] AcceptGenerateKeySize = new int[]
        {
            16, 24, 32, 128, 192, 256
        };
        private int[] AcceptImportKeySize = new int[]
        {
            16, 24, 32
        };
        private int[] AcceptGenerateIvSize = new int[]
        {
            12, 16, 96, 128
        };
        private int[] AcceptImportIvSize = new int[]
        {
            12, 16
        };

        private byte[] Key { get; set; }
        private byte[] IV { get; set; }
        private byte[] Tag { get; set; }
        private byte[] Aad { get; set; }

        public Aes() { }

        public byte[] GenerateKey(int size)
        {
            if (!this.AcceptGenerateKeySize.Contains(size))
                throw new FormatException("Key size must be 128, 192, 256 bits, or 16, 24, 32 bytes.");
            byte[] key = size > 32
                ? new byte[size / 8]
                : new byte[size];
            AesIOInterop.GenerateKey(key, size > 32 ? size / 8 : size);
            this.Key = key;
            return key;
        }

        public byte[] GenerateIV(int size)
        {
            if (!this.AcceptGenerateIvSize.Contains(size))
                throw new FormatException("IV size must be 96, 128 bits, or 12, 16 bytes.");
            byte[] iv = size > 16
                ? new byte[size / 8]
                : new byte[size];
            AesIOInterop.GenerateIV(iv, size > 16 ? size / 8 : size);
            this.IV = iv;
            return iv;
        }

        public byte[] GenerateTag()
        {
            byte[] tag = new byte[16];
            AesIOInterop.GenerateTag(tag, 16);
            this.Tag = tag;
            return tag;
        }

        public byte[] GenerateAad(int size)
        {
            byte[] aad = new byte[16];
            AesIOInterop.GenerateAad(aad, size);
            this.Aad = aad;
            return aad;
        }

        public byte[] ImportKey(string content)
        {
            if (!this.AcceptImportKeySize.Contains(content.Length))
                throw new FormatException("Key size must be 128, 192, 256 bits, or 16, 24, 32 bytes.");
            byte[] key = new byte[content.Length];
            AesIOInterop.ImportKey(content, content.Length, key, key.Length);
            this.Key = key;
            return key;
        }

        public byte[] ImportIV(string content)
        {
            if (!this.AcceptImportIvSize.Contains(content.Length))
                    throw new FormatException("IV size must be 96, 128 bits, or 12, 16 bytes.");
            byte[] iv = new byte[content.Length];
            AesIOInterop.ImportIV(content, content.Length, iv, iv.Length);
            this.IV = iv;
            return iv;
        }

        public byte[] ImportTag(string content)
        {
            if (content.Length != 16)
                throw new FormatException("Tag size must be 128 bits, or 16 bytes.");
            byte[] tag = new byte[content.Length];
            AesIOInterop.ImportTag(content, content.Length, tag, tag.Length);
            this.Tag = tag;
            return tag;
        }

        public byte[] ImportAad(string content)
        {
            byte[] aad = new byte[content.Length];
            AesIOInterop.ImportAad(content, content.Length, aad, aad.Length);
            this.Aad = aad;
            return aad;
        }

        public byte[] CtrEncrypt(byte[] plainText, byte[] key, long counter = 0)
        {
            byte[] cipherText = new byte[plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);

            try
            {
                AES_CTR_ENCRYPT encryption = new AES_CTR_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    COUNTER = counter,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };

                int cipherTextLength = AesIOInterop.AesCtrEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
            }
        }

        public byte[] CtrDecrypt(byte[] cipherText, byte[] key, long counter = 0)
        {
            byte[] plainText = new byte[cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);

            try
            {
                AES_CTR_DECRYPT decryption = new AES_CTR_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    COUNTER = counter,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = AesIOInterop.AesCtrDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] CbcEncrypt(byte[] plainText, byte[] key, byte[] iv, bool padding = true)
        {
            byte[] cipherText = new byte[padding ? plainText.Length + 16 : plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);

            try
            {
                AES_CBC_ENCRYPT encryption = new AES_CBC_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };

                int cipherTextLength = AesIOInterop.AesCbcEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
            }
        }

        public byte[] CbcDecrypt(byte[] cipherText, byte[] key, byte[] iv, bool padding = true)
        {
            byte[] plainText = new byte[padding ? cipherText.Length + 16 : cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);

            try
            {
                AES_CBC_DECRYPT decryption = new AES_CBC_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = AesIOInterop.AesCbcDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] CfbEncrypt(byte[] plainText, byte[] key, byte[] iv, SEGMENT_SIZE_OPTION segmentSize)
        {
            byte[] cipherText = new byte[plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);

            try
            {
                AES_CFB_ENCRYPT encryption = new AES_CFB_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    SEGMENT_SIZE = segmentSize,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };
                int cipherTextLength = AesIOInterop.AesCfbEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] CfbDecrypt(byte[] cipherText, byte[] key, byte[] iv, SEGMENT_SIZE_OPTION segmentSize)
        {
            byte[] plainText = new byte[cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);

            try
            {
                AES_CFB_DECRYPT decryption = new AES_CFB_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    SEGMENT_SIZE = segmentSize,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = AesIOInterop.AesCfbDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] OfbEncrypt(byte[] plainText, byte[] key, byte[] iv)
        {
            byte[] cipherText = new byte[plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);

            try
            {
                AES_OFB_ENCRYPT encryption = new AES_OFB_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };
                int cipherTextLength = AesIOInterop.AesOfbEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] OfbDecrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            byte[] plainText = new byte[cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);

            try
            {
                AES_OFB_DECRYPT decryption = new AES_OFB_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = AesIOInterop.AesOfbDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] EcbEncrypt(byte[] plainText, byte[] key, bool padding = true)
        {
            byte[] cipherText = new byte[padding ? plainText.Length + 16 : plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);

            try
            {
                AES_ECB_ENCRYPT encryption = new AES_ECB_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };
                int cipherTextLength = AesIOInterop.AesEcbEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] EcbDecrypt(byte[] cipherText, byte[] key, bool padding = true)
        {
            byte[] plainText = new byte[padding ? cipherText.Length + 16 : cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);

            try
            {
                AES_ECB_DECRYPT decryption = new AES_ECB_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = AesIOInterop.AesEcbDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] GcmEncrypt(byte[] plainText, byte[] key, byte[] iv, byte[] tag, byte[] aad)
        {
            byte[] cipherText = new byte[plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
            GCHandle aadHandle = GCHandle.Alloc(aad, GCHandleType.Pinned);

            try
            {
                AES_GCM_ENCRYPT encryption = new AES_GCM_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    TAG = tagHandle.AddrOfPinnedObject(),
                    AAD = aadHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    IV_LENGTH = (UIntPtr)iv.Length,
                    TAG_LENGTH = (UIntPtr)tag.Length,
                    AAD_LENGTH = (UIntPtr)aad.Length,
                };

                int cipherTextLength = AesIOInterop.AesGcmEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (tagHandle.IsAllocated) tagHandle.Free();
            }
        }

        public byte[] GcmDecrypt(byte[] cipherText, byte[] key, byte[] iv, byte[] tag, byte[] aad)
        {
            byte[] plainText = new byte[cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
            GCHandle aadHandle = GCHandle.Alloc(aad, GCHandleType.Pinned);

            try
            {
                AES_GCM_DECRYPT decryption = new AES_GCM_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    TAG = tagHandle.AddrOfPinnedObject(),
                    AAD = aadHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    IV_LENGTH = (UIntPtr)iv.Length,
                    TAG_LENGTH = (UIntPtr)tag.Length,
                    AAD_LENGTH = (UIntPtr)aad.Length,
                };

                int plainTextLength = AesIOInterop.AesGcmDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (tagHandle.IsAllocated) tagHandle.Free();
            }
        }

        public byte[] CcmEncrypt(byte[] plainText, byte[] key, byte[] iv, byte[] tag, byte[] aad)
        {
            byte[] cipherText = new byte[plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
            GCHandle aadHandle = GCHandle.Alloc(aad, GCHandleType.Pinned);

            try
            {
                AES_CCM_ENCRYPT encryption = new AES_CCM_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    TAG = tagHandle.AddrOfPinnedObject(),
                    AAD = aadHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    IV_LENGTH = (UIntPtr)iv.Length,
                    TAG_LENGTH = (UIntPtr)tag.Length,
                    AAD_LENGTH = (UIntPtr)aad.Length,
                };

                int cipherTextLength = AesIOInterop.AesCcmEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (tagHandle.IsAllocated) tagHandle.Free();
                if (aadHandle.IsAllocated) aadHandle.Free();
            }
        }

        public byte[] CcmDecrypt(byte[] cipherText, byte[] key, byte[] iv, byte[] tag, byte[] aad)
        {
            byte[] plainText = new byte[cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
            GCHandle aadHandle = GCHandle.Alloc(aad, GCHandleType.Pinned);

            try
            {
                AES_CCM_DECRYPT decryption = new AES_CCM_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    TAG = tagHandle.AddrOfPinnedObject(),
                    AAD = aadHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    IV_LENGTH = (UIntPtr)iv.Length,
                    TAG_LENGTH = (UIntPtr)tag.Length,
                    AAD_LENGTH = (UIntPtr)aad.Length
                };

                int plainTextLength = AesIOInterop.AesCcmDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (tagHandle.IsAllocated) tagHandle.Free();
                if (aadHandle.IsAllocated) aadHandle.Free();
            }
        }

        public byte[] XtsEncrypt(byte[] plainText, byte[] key1, byte[] key2, byte[] tweak)
        {
            byte[] cipherText = new byte[plainText.Length];

            GCHandle key1Handle = GCHandle.Alloc(key1, GCHandleType.Pinned);
            GCHandle key2Handle = GCHandle.Alloc(key2, GCHandleType.Pinned);
            GCHandle tweakHandle = GCHandle.Alloc(tweak, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);

            try
            {
                AES_XTS_ENCRYPT encryption = new AES_XTS_ENCRYPT
                {
                    KEY1 = key1Handle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    KEY2 = key2Handle.AddrOfPinnedObject(),
                    TWEAK = tweakHandle.AddrOfPinnedObject(),
                    KEY1_LENGTH = (UIntPtr)key1.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    KEY2_LENGTH = (UIntPtr)key2.Length,
                };

                int cipherTextLength = AesIOInterop.AesXtsEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (key1Handle.IsAllocated) key1Handle.Free();
                if (key2Handle.IsAllocated) key2Handle.Free();
                if (tweakHandle.IsAllocated) tweakHandle.Free();
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
            }
        }

        public byte[] XtsDecrypt(byte[] cipherText, byte[] key1, byte[] key2, byte[] tweak)
        {
            byte[] plainText = new byte[cipherText.Length];

            GCHandle key1Handle = GCHandle.Alloc(key1, GCHandleType.Pinned);
            GCHandle key2Handle = GCHandle.Alloc(key2, GCHandleType.Pinned);
            GCHandle tweakHandle = GCHandle.Alloc(tweak, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);

            try
            {
                AES_XTS_DECRYPT decryption = new AES_XTS_DECRYPT
                {
                    KEY1 = key1Handle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    KEY2 = key2Handle.AddrOfPinnedObject(),
                    TWEAK = tweakHandle.AddrOfPinnedObject(),
                    KEY1_LENGTH = (UIntPtr)key1.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    KEY2_LENGTH = (UIntPtr)key2.Length,
                };

                int plainTextLength = AesIOInterop.AesXtsDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (key1Handle.IsAllocated) key1Handle.Free();
                if (key2Handle.IsAllocated) key2Handle.Free();
                if (tweakHandle.IsAllocated) tweakHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
            }
        }

        public byte[] OcbEncrypt(byte[] plainText, byte[] key, byte[] iv, byte[] tag, byte[] aad)
        {
            byte[] cipherText = new byte[plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
            GCHandle aadHandle = GCHandle.Alloc(aad, GCHandleType.Pinned);

            try
            {
                AES_OCB_ENCRYPT encryption = new AES_OCB_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    TAG = tagHandle.AddrOfPinnedObject(),
                    AAD = aadHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    IV_LENGTH = (UIntPtr)iv.Length,
                    TAG_LENGTH = (UIntPtr)tag.Length,
                    AAD_LENGTH = (UIntPtr)aad.Length,
                };

                int cipherTextLength = AesIOInterop.AesOcbEncrypt(ref encryption);
                if (cipherTextLength > 0)
                {
                    byte[] result = new byte[cipherTextLength];
                    Array.Copy(cipherText, result, cipherTextLength);
                    cipherText = result;
                }
                else
                    cipherText = new byte[0];

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (tagHandle.IsAllocated) tagHandle.Free();
                if (aadHandle.IsAllocated) aadHandle.Free();
            }
        }

        public byte[] OcbDecrypt(byte[] cipherText, byte[] key, byte[] iv, byte[] tag, byte[] aad)
        {
            byte[] plainText = new byte[cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
            GCHandle aadHandle = GCHandle.Alloc(aad, GCHandleType.Pinned);

            try
            {
                AES_OCB_DECRYPT decryption = new AES_OCB_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    TAG = tagHandle.AddrOfPinnedObject(),
                    AAD = aadHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    IV_LENGTH = (UIntPtr)iv.Length,
                    TAG_LENGTH = (UIntPtr)tag.Length,
                    AAD_LENGTH = (UIntPtr)aad.Length,
                };

                int plainTextLength = AesIOInterop.AesOcbDecrypt(ref decryption);
                if (plainTextLength > 0)
                {
                    byte[] result = new byte[plainTextLength];
                    Array.Copy(plainText, result, plainTextLength);
                    plainText = result;
                }
                else
                    plainText = new byte[0];

                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (cipherTextHandle.IsAllocated) cipherTextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (plainTextHandle.IsAllocated) plainTextHandle.Free();
                if (tagHandle.IsAllocated) tagHandle.Free();
                if (aadHandle.IsAllocated) aadHandle.Free();
            }
        }

        public byte[] WrapEncrypt(byte[] plainKey, byte[] wrappingKey)
        {
            byte[] wrappedKey = new byte[plainKey.Length + 8]; // Wrapped key length is input length + 8 bytes.
            
            GCHandle plainKeyHandle = GCHandle.Alloc(plainKey, GCHandleType.Pinned);
            GCHandle wrappingKeyHandle = GCHandle.Alloc(wrappingKey, GCHandleType.Pinned);
            GCHandle wrappedKeyHandle = GCHandle.Alloc(wrappedKey, GCHandleType.Pinned);

            try
            {
                AES_WRAP_ENCRYPT encryption = new AES_WRAP_ENCRYPT
                {
                    KEY = plainKeyHandle.AddrOfPinnedObject(),
                    KEK = wrappingKeyHandle.AddrOfPinnedObject(),
                    WRAP_KEY = wrappedKeyHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)plainKey.Length,
                    KEK_LENGTH = (UIntPtr)wrappingKey.Length,
                    WRAP_KEY_LENGTH = (UIntPtr)wrappedKey.Length,
                };

                int wrappedKeyLength = AesIOInterop.AesWrapEncrypt(ref encryption);
                if (wrappedKeyLength > 0)
                {
                    byte[] result = new byte[wrappedKeyLength];
                    Array.Copy(wrappedKey, result, wrappedKeyLength);
                    wrappedKey = result;
                }
                else
                    wrappedKey = new byte[0];

                return wrappedKey;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}: {ex.StackTrace}");
                return new byte[0];
            }
            finally
            {
                if (plainKeyHandle.IsAllocated) plainKeyHandle.Free();
                if (wrappingKeyHandle.IsAllocated) wrappingKeyHandle.Free();
                if (wrappedKeyHandle.IsAllocated) wrappedKeyHandle.Free();
            }
        }

        public byte[] WrapDecrypt(byte[] wrappedKey, byte[] wrappingKey)
        {
            byte[] unwrappedKey = new byte[wrappedKey.Length - 8];
            
            GCHandle wrappedKeyHandle = GCHandle.Alloc(wrappedKey, GCHandleType.Pinned);
            GCHandle wrappingKeyHandle = GCHandle.Alloc(wrappingKey, GCHandleType.Pinned);
            GCHandle unwrappedKeyHandle = GCHandle.Alloc(unwrappedKey, GCHandleType.Pinned);

            try
            {
                AES_WRAP_DECRYPT decryption = new AES_WRAP_DECRYPT
                {
                    WRAP_KEY = wrappedKeyHandle.AddrOfPinnedObject(),
                    WRAP_KEY_LENGTH = (UIntPtr)wrappedKey.Length,
                    KEK = wrappingKeyHandle.AddrOfPinnedObject(),
                    KEK_LENGTH = (UIntPtr)wrappingKey.Length,
                    KEY = unwrappedKeyHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)unwrappedKey.Length,
                };

                int unwrappedKeyLength = AesIOInterop.AesWrapDecrypt(ref decryption);
                if (unwrappedKeyLength > 0)
                {
                    byte[] result = new byte[unwrappedKeyLength];
                    Array.Copy(unwrappedKey, result, unwrappedKeyLength);
                    unwrappedKey = result;
                }
                else
                    unwrappedKey = new byte[0];

                return unwrappedKey;
            }
            finally
            {
                if (wrappedKeyHandle.IsAllocated) wrappedKeyHandle.Free();
                if (wrappingKeyHandle.IsAllocated) wrappingKeyHandle.Free();
                if (unwrappedKeyHandle.IsAllocated) unwrappedKeyHandle.Free();
            }
        }
    }
}
