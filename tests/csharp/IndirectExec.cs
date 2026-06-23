using System;
using System.Diagnostics;

class IndirectExec {
    static void Main(string[] args) {
        string cmd = args[0];
        // Indirect call: assign Process.Start to Action
        Action<string> func = (c) => {
            Process.Start(new ProcessStartInfo(c) { UseShellExecute = true });
        };
        func(cmd);
    }
}
