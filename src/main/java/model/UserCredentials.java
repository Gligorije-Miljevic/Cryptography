package model;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class UserCredentials {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private X509Certificate certificate;

    public UserCredentials(PublicKey publicKey, PrivateKey privateKey, X509Certificate certificate) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.certificate = certificate;
    }
    public PublicKey getPublicKey() { return publicKey; }
    public PrivateKey getPrivateKey() { return privateKey; }
    public X509Certificate getCertificate() { return certificate; }
}
