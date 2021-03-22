package rsa;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Util {
    public static byte[] readFileAsBytes(String filename) throws IOException {
        FileInputStream file = new FileInputStream(filename);
        byte[] bytes = new byte[file.available()];
        file.read(bytes);
        file.close();
        return bytes;
    }
}
