using Ais.IO.Csharp;
using System.Text;

namespace Ais.IO.Csharp.Command
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                //BinaryIO.WriteRelease();
                //BinaryIO.ReadRelease();
                //EncoderIO.BaseEncode(out byte[] b16, out byte[] b32, out byte[] b64, out byte[] b85);
                //EncoderIO.BaseDecode(b16, b32, b64, b85);

                AesIO.Generate();

                //StructT.GetStruct();
                Console.WriteLine("Press Any Key To Continue...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }
}