package crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyPairService {

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }
}
