using System;
using DynSec_Wrapper;
namespace NETTestingGrounds
{
    class Program
    {
        static void Log(string msg, params object[] param)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(msg, param);
            Console.ResetColor();
        }
        static void Main(string[] args)
        {
            Log("Initializing...!");
            DynSecAntiCheat.Initialize(new Callbacks());
            Log("DynSec loaded in C# !");

            Console.ReadLine();
        }
    }
}
