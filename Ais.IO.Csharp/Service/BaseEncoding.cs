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
        Base10,
        Base16,
        Base32,
        Base58,
        Base62,
        Base64,
        Base85,
        Base91,
    }

    public class BaseEncoding
    {
        private EncodingType _type;
        public EncodingType Type => _type;

        public BaseEncoding()
            => this._type = EncodingType.None;

        public BaseEncoding(EncodingType type)
            => this._type = type;

        public long GetEncodeLength(long inputLength, EncodingType type)
        {
            switch (type)
            {
                case EncodingType.Base10:
                    return EncoderIOInterop.Base10Length(inputLength, true);
                case EncodingType.Base16:
                    return EncoderIOInterop.Base16Length(inputLength, true);
                case EncodingType.Base32:
                    return EncoderIOInterop.Base32Length(inputLength, true);
                case EncodingType.Base58:
                    return EncoderIOInterop.Base58Length(inputLength, true);
                case EncodingType.Base62:
                    return EncoderIOInterop.Base62Length(inputLength, true);
                case EncodingType.Base64:
                    return EncoderIOInterop.Base64Length(inputLength, true);
                case EncodingType.Base85:
                    return EncoderIOInterop.Base85Length(inputLength, true);
                case EncodingType.Base91:
                    return EncoderIOInterop.Base91Length(inputLength, true);
                default:
                    return 0;
            }
        }

        public long GetDecodeLength(long inputLength, EncodingType type)
        {
            switch (type)
            {
                case EncodingType.Base10:
                    return EncoderIOInterop.Base10Length(inputLength, false);
                case EncodingType.Base16:
                    return EncoderIOInterop.Base16Length(inputLength, false);
                case EncodingType.Base32:
                    return EncoderIOInterop.Base32Length(inputLength, false);
                case EncodingType.Base58:
                    return EncoderIOInterop.Base58Length(inputLength, false);
                case EncodingType.Base62:
                    return EncoderIOInterop.Base62Length(inputLength, false);
                case EncodingType.Base64:
                    return EncoderIOInterop.Base64Length(inputLength, false);
                case EncodingType.Base85:
                    return EncoderIOInterop.Base85Length(inputLength, false);
                case EncodingType.Base91:
                    return EncoderIOInterop.Base91Length(inputLength, false);
                default:
                    return 0;
            }
        }

        public string Encode(byte[] content, EncodingType type = EncodingType.None)
        {
            if (type == EncodingType.None && this.Type != EncodingType.None)
                type = this.Type;
            else if (type == EncodingType.None && this.Type == EncodingType.None)
                throw new ArgumentException("EncodingType is none.");
            byte[] input = content;
            StringBuilder output = new StringBuilder();
            long outputLength = this.GetEncodeLength(input.LongLength, type);
            output.Length = (int)outputLength;
            switch (type)
            {
                case EncodingType.Base10:
                    EncoderIOInterop.Base10Encode(input, input.LongLength, output, outputLength);
                    break;
                case EncodingType.Base16:
                    EncoderIOInterop.Base16Encode(input, input.LongLength, output, outputLength);
                    break;
                case EncodingType.Base32:
                    EncoderIOInterop.Base32Encode(input, input.LongLength, output, outputLength);
                    break;
                case EncodingType.Base58:
                    EncoderIOInterop.Base58Encode(input, input.LongLength, output, outputLength);
                    break;
                case EncodingType.Base62:
                    EncoderIOInterop.Base62Encode(input, input.LongLength, output, outputLength);
                    break;
                case EncodingType.Base64:
                    EncoderIOInterop.Base64Encode(input, input.LongLength, output, outputLength);
                    break;
                case EncodingType.Base85:
                    EncoderIOInterop.Base85Encode(input, input.LongLength, output, outputLength);
                    break;
                case EncodingType.Base91:
                    EncoderIOInterop.Base91Encode(input, input.LongLength, output, outputLength);
                    break;
            }
            return output.Length == 0 ? string.Empty : output.ToString();
        }

        public byte[] Decode(string content, EncodingType type = EncodingType.None)
        {
            if (type == EncodingType.None && this.Type != EncodingType.None)
                type = this.Type;
            else if (type == EncodingType.None && this.Type == EncodingType.None)
                throw new ArgumentException("EncodingType is none.");
            StringBuilder input = new StringBuilder(content);
            long outputLength = this.GetDecodeLength(content.LongCount(), type);
            byte[] output = new byte[outputLength];
            switch (type)
            {
                case EncodingType.Base10:
                    EncoderIOInterop.Base10Decode(input, content.LongCount(), output, outputLength);
                    break;
                case EncodingType.Base16:
                    EncoderIOInterop.Base16Decode(input, content.LongCount(), output, outputLength);
                    break;
                case EncodingType.Base32:
                    EncoderIOInterop.Base32Decode(input, content.LongCount(), output, outputLength);
                    break;
                case EncodingType.Base58:
                    EncoderIOInterop.Base58Decode(input, content.LongCount(), output, outputLength);
                    break;
                case EncodingType.Base62:
                    EncoderIOInterop.Base62Decode(input, content.LongCount(), output, outputLength);
                    break;
                case EncodingType.Base64:
                    EncoderIOInterop.Base64Decode(input, content.LongCount(), output, outputLength);
                    break;
                case EncodingType.Base85:
                    EncoderIOInterop.Base85Decode(input, content.LongCount(), output, outputLength);
                    break;
                case EncodingType.Base91:
                    EncoderIOInterop.Base91Decode(input, content.LongCount(), output, outputLength);
                    break;
            }
            return output.Length == 0 ? new byte[0] : output;
        }
    }
}
