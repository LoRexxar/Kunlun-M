import java.io.*;

public class IndirectExec {
    // Indirect call: Runnable wraps Runtime.exec
    public static void main(String[] args) throws Exception {
        String cmd = args[0];
        // Indirect call via lambda
        Runnable r = () -> {
            try { Runtime.getRuntime().exec(cmd); } catch (Exception e) {}
        };
        r.run();
    }
}
