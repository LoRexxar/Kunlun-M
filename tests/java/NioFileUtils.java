import java.io.*;
import java.nio.file.*;

public class NioFileUtils {
    // TP: Files.readAllBytes with user-controlled path
    public static void readAll(String path) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(path));
    }

    // TP: Files.readAllLines with user-controlled path
    public static void readLines(String path) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(path));
    }

    // TP: Files.write with user-controlled path
    public static void writeFile(String path, String content) throws Exception {
        Files.write(Paths.get(path), content.getBytes());
    }

    // TP: RandomAccessFile with user-controlled path
    public static void randomRead(String path) throws Exception {
        RandomAccessFile raf = new RandomAccessFile(path, "r");
    }

    // Safe: hardcoded path
    public static void safeRead() throws Exception {
        byte[] data = Files.readAllBytes(Paths.get("/etc/hostname"));
    }
}
