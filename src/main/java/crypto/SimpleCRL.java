package crypto;

import java.nio.file.*;
import java.util.*;
import java.math.BigInteger;

public class SimpleCRL {
    private final Path crlFile;

    public SimpleCRL(Path crlFile) { this.crlFile = crlFile; }

    public boolean isRevoked(BigInteger serial) throws Exception {
        if (Files.notExists(crlFile)) return false;
        for (String line : Files.readAllLines(crlFile)) {
            if (line.trim().equals(serial.toString())) return true;
        }
        return false;
    }

    public void revoke(BigInteger serial) throws Exception {
        Files.createDirectories(crlFile.getParent());
        Files.writeString(crlFile, serial.toString() + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
