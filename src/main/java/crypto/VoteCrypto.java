package crypto;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;

public class VoteCrypto {

    public static SecretKey genAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    public static class AesGcmResult {
        public final byte[] iv;
        public final byte[] ct;
        public AesGcmResult(byte[] iv, byte[] ct){ this.iv=iv; this.ct=ct; }
    }

    public static AesGcmResult aesGcmEncrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plaintext);
        return new AesGcmResult(iv, ct);
    }

    public static byte[] aesGcmDecrypt(byte[] iv, byte[] ciphertext, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(ciphertext);
    }

    public static byte[] rsaOaepEncrypt(byte[] data, PublicKey pub) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }

    public static byte[] rsaOaepDecrypt(byte[] data, PrivateKey priv) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal(data);
    }

    public static byte[] sign(byte[] data, PrivateKey priv) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        s.initSign(priv);
        s.update(data);
        return s.sign();
    }

    public static boolean verify(byte[] data, byte[] sig, PublicKey pub) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        s.initVerify(pub);
        s.update(data);
        return s.verify(sig);
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }
}
