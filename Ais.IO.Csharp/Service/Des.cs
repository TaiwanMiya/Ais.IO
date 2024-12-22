using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public class Des : Symmetry
    {
        public Des() { }

        public byte[] CbcEncrypt(byte[] plainText, byte[] key, byte[] iv, bool padding = true)
        {
            byte[] cipherText = new byte[padding ? plainText.Length + 8 : plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);

            try
            {
                DES_CBC_ENCRYPT encryption = new DES_CBC_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };

                int cipherTextLength = DesIOInterop.DesCbcEncrypt(ref encryption);
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
            byte[] plainText = new byte[padding ? cipherText.Length + 8 : cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);

            try
            {
                DES_CBC_DECRYPT decryption = new DES_CBC_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = DesIOInterop.DesCbcDecrypt(ref decryption);
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
                DES_CFB_ENCRYPT encryption = new DES_CFB_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    SEGMENT_SIZE = segmentSize,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };
                int cipherTextLength = DesIOInterop.DesCfbEncrypt(ref encryption);
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
                DES_CFB_DECRYPT decryption = new DES_CFB_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    SEGMENT_SIZE = segmentSize,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = DesIOInterop.DesCfbDecrypt(ref decryption);
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
                DES_OFB_ENCRYPT encryption = new DES_OFB_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };
                int cipherTextLength = DesIOInterop.DesOfbEncrypt(ref encryption);
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
                DES_OFB_DECRYPT decryption = new DES_OFB_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    IV = ivHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = DesIOInterop.DesOfbDecrypt(ref decryption);
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
            byte[] cipherText = new byte[padding ? plainText.Length + 8 : plainText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);

            try
            {
                DES_ECB_ENCRYPT encryption = new DES_ECB_ENCRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    PLAIN_TEXT_LENGTH = (UIntPtr)plainText.Length,
                };

                int cipherTextLength = DesIOInterop.DesEcbEncrypt(ref encryption);
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

        public byte[] EcbDecrypt(byte[] cipherText, byte[] key, bool padding = true)
        {
            byte[] plainText = new byte[padding ? cipherText.Length + 8 : cipherText.Length];

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            GCHandle cipherTextHandle = GCHandle.Alloc(cipherText, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);

            try
            {
                DES_ECB_DECRYPT decryption = new DES_ECB_DECRYPT
                {
                    KEY = keyHandle.AddrOfPinnedObject(),
                    CIPHER_TEXT = cipherTextHandle.AddrOfPinnedObject(),
                    PLAIN_TEXT = plainTextHandle.AddrOfPinnedObject(),
                    PKCS7_PADDING = padding,
                    KEY_LENGTH = (UIntPtr)key.Length,
                    CIPHER_TEXT_LENGTH = (UIntPtr)cipherText.Length,
                };
                int plainTextLength = DesIOInterop.DesEcbDecrypt(ref decryption);
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

        public byte[] WrapEncrypt(byte[] plainKey, byte[] wrappingKey)
        {
            byte[] wrappedKey = new byte[plainKey.Length + 16]; // Wrapped key length is input length + 16 bytes.

            GCHandle plainKeyHandle = GCHandle.Alloc(plainKey, GCHandleType.Pinned);
            GCHandle wrappingKeyHandle = GCHandle.Alloc(wrappingKey, GCHandleType.Pinned);
            GCHandle wrappedKeyHandle = GCHandle.Alloc(wrappedKey, GCHandleType.Pinned);

            try
            {
                DES_WRAP_ENCRYPT encryption = new DES_WRAP_ENCRYPT
                {
                    KEY = plainKeyHandle.AddrOfPinnedObject(),
                    KEK = wrappingKeyHandle.AddrOfPinnedObject(),
                    WRAP_KEY = wrappedKeyHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)plainKey.Length,
                    KEK_LENGTH = (UIntPtr)wrappingKey.Length,
                    WRAP_KEY_LENGTH = (UIntPtr)wrappedKey.Length,
                };

                int wrappedKeyLength = DesIOInterop.DesWrapEncrypt(ref encryption);
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
            byte[] unwrappedKey = new byte[wrappedKey.Length - 16];

            GCHandle wrappedKeyHandle = GCHandle.Alloc(wrappedKey, GCHandleType.Pinned);
            GCHandle wrappingKeyHandle = GCHandle.Alloc(wrappingKey, GCHandleType.Pinned);
            GCHandle unwrappedKeyHandle = GCHandle.Alloc(unwrappedKey, GCHandleType.Pinned);

            try
            {
                DES_WRAP_DECRYPT decryption = new DES_WRAP_DECRYPT
                {
                    WRAP_KEY = wrappedKeyHandle.AddrOfPinnedObject(),
                    WRAP_KEY_LENGTH = (UIntPtr)wrappedKey.Length,
                    KEK = wrappingKeyHandle.AddrOfPinnedObject(),
                    KEK_LENGTH = (UIntPtr)wrappingKey.Length,
                    KEY = unwrappedKeyHandle.AddrOfPinnedObject(),
                    KEY_LENGTH = (UIntPtr)unwrappedKey.Length,
                };

                int unwrappedKeyLength = DesIOInterop.DesWrapDecrypt(ref decryption);
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
