package crypto;

import java.nio.file.*;
import java.security.SecureRandom;

public final class HmacKeyStore {
    private static final Path KEY_PATH = Path.of("storage", "hmac", "master.key");
    private static byte[] cached;

    private HmacKeyStore() {}

    public static synchronized byte[] getOrCreate() throws Exception {
        if (cached != null) return cached;

        Files.createDirectories(KEY_PATH.getParent());

        if (Files.exists(KEY_PATH)) {
            cached = Files.readAllBytes(KEY_PATH);
            if (cached.length != 32) throw new IllegalStateException("HMAC key invalid length");
            return cached;
        }

        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        Files.write(KEY_PATH, key, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        cached = key;
        return cached;
    }
}
