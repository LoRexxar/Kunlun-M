import java.io.*;
import javax.servlet.http.*;

public class CmdInject extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cmd = request.getParameter("cmd");
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.start();
    }
}
