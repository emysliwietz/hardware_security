package utility;

import java.io.*;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import static utility.Util.print;

public class Logger {

    public enum level{INFO, WARNING, FATAL}
    private PrintWriter pw;

    public Logger(File logFile){
        try {
            FileWriter fw = new FileWriter(logFile, true);
            BufferedWriter bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void log(String message, level lvl, String msgSrc){
        String timestamp = ZonedDateTime.now(
                ZoneId.of("Europe/Amsterdam")
        ).toString();
        String lvls = " ".repeat(level.WARNING.toString().length() - lvl.toString().length()) + lvl.toString()+ " ";
        String toFile = timestamp + lvls + message + " (" + msgSrc + ")";
        pw.println(toFile);
    }
}
