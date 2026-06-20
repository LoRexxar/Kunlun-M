using System.Diagnostics;
class Program {
    static void Main(string[] args) {
        Process.Start("cmd", "/c " + args[0]);
    }
}
