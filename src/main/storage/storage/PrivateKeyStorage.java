package storage;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

public class PrivateKeyStorage {

    private static final int ITER = 65536;
    private static final int KEY_LEN = 256;

    public static void saveEncryptedPrivateKey(PrivateKey privateKey, String password, String filePath) throws Exception {

        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(salt);
        rnd.nextBytes(iv);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey tmp = skf.generateSecret(
                new PBEKeySpec(password.toCharArray(), salt, ITER, KEY_LEN)
        );
        SecretKey aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

        byte[] encrypted = cipher.doFinal(privateKey.getEncoded());

        Files.createDirectories(Path.of(filePath).getParent());

        try (DataOutputStream out = new DataOutputStream(new FileOutputStream(filePath))) {
            out.writeInt(salt.length);
            out.write(salt);
            out.writeInt(iv.length);
            out.write(iv);
            out.writeInt(encrypted.length);
            out.write(encrypted);
        }
    }

    public static PrivateKey loadEncryptedPrivateKey(String filePath, String password) throws Exception {

        try (DataInputStream in = new DataInputStream(new FileInputStream(filePath))) {

            byte[] salt = new byte[in.readInt()];
            in.readFully(salt);

            byte[] iv = new byte[in.readInt()];
            in.readFully(iv);

            byte[] encrypted = new byte[in.readInt()];
            in.readFully(encrypted);

            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey tmp = skf.generateSecret(
                    new PBEKeySpec(password.toCharArray(), salt, ITER, KEY_LEN)
            );
            SecretKey aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));

            byte[] keyBytes = cipher.doFinal(encrypted);

            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }
    }
}
