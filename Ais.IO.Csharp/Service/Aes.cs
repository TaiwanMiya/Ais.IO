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

        private byte[] Key { get; set; }
        private byte[] IV { get; set; }

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

        public byte[] GenerateIV()
        {
            byte[] iv = new byte[16];
            AesIOInterop.GenerateIV(iv, 16);
            this.IV = iv;
            return iv;
        }

        public byte[] ImportKey(string content)
        {
            if (!this.AcceptImportKeySize.Contains(content.Length))
                throw new FormatException("Key size must be 128, 192, 256 bits, or 16, 24, 32 bytes.");
            byte[] key = new byte[content.Length];
            byte[] keyBuffer = new byte[key.Length];
            AesIOInterop.GenerateKeyFromInput(content, content.Length, keyBuffer, keyBuffer.Length);
            this.Key = keyBuffer;
            return keyBuffer;
        }

        public byte[] ImportIV(string content)
        {
            if (content.Length != 16)
                throw new FormatException("IV size must be 128 bits, or 16 bytes.");
            byte[] iv = new byte[content.Length];
            byte[] ivBuffer = new byte[iv.Length];
            AesIOInterop.GenerateIVFromInput(content, content.Length, ivBuffer, ivBuffer.Length);
            this.IV = ivBuffer;
            return ivBuffer;
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
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    COUNTER = counter,
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
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    COUNTER = counter,
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
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding
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
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding
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
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    SEGMENT_SIZE = segmentSize
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
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    SEGMENT_SIZE = segmentSize
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
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
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
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject()
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
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding
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
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    KEY = keyHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding
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
    }
}
