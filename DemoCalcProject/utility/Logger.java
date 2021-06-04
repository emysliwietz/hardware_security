package utility;

import java.io.*;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;

public class Logger {

    private PrintWriter pw;

    public Logger(File logFile) {
        try {
            FileWriter fw = new FileWriter(logFile, true);
            BufferedWriter bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);
        } catch (FileNotFoundException e) {
            System.err.println("File not found");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void log(String message, level lvl, String msgSrc, byte[] cardID) {
        String timestamp = ZonedDateTime.now(
                ZoneId.of("Europe/Amsterdam")
        ).toString();
        String lvls = " ".repeat(1 + level.WARNING.toString().length() - lvl.toString().length()) + lvl + " ";
        String toFile = timestamp + lvls + "(" + Arrays.toString(cardID) + ") " + message + " (Source: " + msgSrc + ")";
        try {
            pw.println(toFile);
        } catch (NullPointerException e) {
            System.err.println("Printer not initialized");
        }
        System.out.println(toFile);
    }

    public void info(String message, String msgSrc, byte[] cardID) {
        log(message, level.INFO, msgSrc, cardID);
    }

    public void warning(String message, String msgSrc, byte[] cardID) {
        log(message, level.WARNING, msgSrc, cardID);
    }

    public void fatal(String message, String msgSrc, byte[] cardID) {
        log(message, level.FATAL, msgSrc, cardID);
    }

    public enum level {INFO, WARNING, FATAL}
}
