using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ais.IO.Csharp
{
    public enum EncodingType
    {
        None,
        Base16,
        Base32,
        Base64,
        Base85,
    }

    public class BaseEncoding
    {
        private EncodingType _type;
        public EncodingType Type => _type;

        public BaseEncoding(EncodingType type)
            => this._type = type;

        private byte[] GetEncodeLength(byte[] input, EncodingType type)
        {
            switch (type)
            {
                case EncodingType.Base16:
                    return new byte[input.Length * 2 + 1];
                case EncodingType.Base32:
                    return new byte[((input.Length + 4) / 5) * 8 + 1];
                case EncodingType.Base64:
                    return new byte[((input.Length + 2) / 3) * 4 + 1];
                case EncodingType.Base85:
                    return new byte[((input.Length + 3) / 4) * 5 + 1];
                default:
                    return new byte[0];
            }
        }

        private byte[] GetDecodeLength(byte[] input, EncodingType type)
        {
            switch (type)
            {
                case EncodingType.Base16:
                    return new byte[input.Length / 2];
                case EncodingType.Base32:
                    return new byte[(input.Length / 8) * 5];
                case EncodingType.Base64:
                    return new byte[(input.Length / 4) * 3];
                case EncodingType.Base85:
                    return new byte[(input.Length / 5) * 4];
                default:
                    return new byte[0];
            }
        }

        public T Encode<T>(string content)
        {
            byte[] input = Encoding.UTF8.GetBytes(content);
            byte[] output = this.GetEncodeLength(input, this.Type);
            switch (this.Type)
            {
                case EncodingType.Base16:
                    EncoderIOInterop.Base16Encode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base32:
                    EncoderIOInterop.Base32Encode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base64:
                    EncoderIOInterop.Base64Encode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base85:
                    EncoderIOInterop.Base85Encode(input, input.LongLength, output, output.LongLength);
                    break;
            }
            if (typeof(T) == typeof(string))
            {
                if (output.Length == 0)
                    return (T)(object)string.Empty;
                else
                    return (T)(object)Encoding.UTF8.GetString(output);
            }
            else if (typeof(T) == typeof(byte[]))
                return (T)(object)output;
            else
                return default;
        }

        public T Encode<T>(byte[] content)
        {
            byte[] input = content;
            byte[] output = this.GetEncodeLength(input, this.Type);
            switch (this.Type)
            {
                case EncodingType.Base16:
                    EncoderIOInterop.Base16Encode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base32:
                    EncoderIOInterop.Base32Encode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base64:
                    EncoderIOInterop.Base64Encode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base85:
                    EncoderIOInterop.Base85Encode(input, input.LongLength, output, output.LongLength);
                    break;
            }
            if (typeof(T) == typeof(string))
            {
                if (output.Length == 0)
                    return (T)(object)string.Empty;
                else
                    return (T)(object)Encoding.UTF8.GetString(output);
            }
            else if (typeof(T) == typeof(byte[]))
                return (T)(object)output;
            else
                return default;
        }

        public T Decode<T>(string content)
        {
            byte[] input = Encoding.UTF8.GetBytes(content);
            byte[] output = this.GetDecodeLength(input, this.Type);
            switch (this.Type)
            {
                case EncodingType.Base16:
                    EncoderIOInterop.Base16Decode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base32:
                    EncoderIOInterop.Base32Decode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base64:
                    EncoderIOInterop.Base64Decode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base85:
                    EncoderIOInterop.Base85Decode(input, input.LongLength, output, output.LongLength);
                    break;
            }
            if (typeof(T) == typeof(string))
            {
                if (output.Length == 0)
                    return (T)(object)string.Empty;
                else
                    return (T)(object)Encoding.UTF8.GetString(output);
            }
            else if (typeof(T) == typeof(byte[]))
                return (T)(object)output;
            else
                return default;
        }

        public T Decode<T>(byte[] content)
        {
            byte[] input = content;
            byte[] output = this.GetDecodeLength(input, this.Type);
            switch (this.Type)
            {
                case EncodingType.Base16:
                    EncoderIOInterop.Base16Decode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base32:
                    EncoderIOInterop.Base32Decode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base64:
                    EncoderIOInterop.Base64Decode(input, input.LongLength, output, output.LongLength);
                    break;
                case EncodingType.Base85:
                    EncoderIOInterop.Base85Decode(input, input.LongLength, output, output.LongLength);
                    break;
            }
            if (typeof(T) == typeof(string))
            {
                if (output.Length == 0)
                    return (T)(object)string.Empty;
                else
                    return (T)(object)Encoding.UTF8.GetString(output);
            }
            else if (typeof(T) == typeof(byte[]))
                return (T)(object)output;
            else
                return default;
        }
    }
}
