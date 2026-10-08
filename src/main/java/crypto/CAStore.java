package crypto;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;

public final class CAStore {
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }
    private static final Path CA_DIR = Paths.get("storage", "ca");

    private static final Path ROOT_KEY = CA_DIR.resolve("root.key.pem");
    private static final Path ROOT_CERT = CA_DIR.resolve("root.cert.pem");

    private static final Path ORG_KEY = CA_DIR.resolve("orgca.key.pem");
    private static final Path ORG_CERT = CA_DIR.resolve("orgca.cert.pem");

    private static final Path VOTER_KEY = CA_DIR.resolve("voterca.key.pem");
    private static final Path VOTER_CERT = CA_DIR.resolve("voterca.cert.pem");

    private static final String ROOT_DN  = "CN=RootCA, O=eVoting, C=BA";
    private static final String ORG_DN   = "CN=OrgCA, O=eVoting, C=BA";
    private static final String VOTER_DN = "CN=VoterCA, O=eVoting, C=BA";

    private static volatile boolean initialized = false;

    private static PrivateKey rootPriv;
    private static X509Certificate rootCert;

    private static PrivateKey orgPriv;
    private static X509Certificate orgCert;

    private static PrivateKey voterPriv;
    private static X509Certificate voterCert;

    private CAStore() {}

    public static String getRootCaDn() throws Exception { ensureInit(); return ROOT_DN; }
    public static String getOrgCaDn() throws Exception { ensureInit(); return ORG_DN; }
    public static String getVoterCaDn() throws Exception { ensureInit(); return VOTER_DN; }

    public static PrivateKey getRootCaPrivateKey() throws Exception { ensureInit(); return rootPriv; }
    public static X509Certificate getRootCaCert() throws Exception { ensureInit(); return rootCert; }

    public static PrivateKey getOrgCaPrivateKey() throws Exception { ensureInit(); return orgPriv; }
    public static X509Certificate getOrgCaCert() throws Exception { ensureInit(); return orgCert; }

    public static PrivateKey getVoterCaPrivateKey() throws Exception { ensureInit(); return voterPriv; }
    public static X509Certificate getVoterCaCert() throws Exception { ensureInit(); return voterCert; }


    private static synchronized void ensureInit() throws Exception {
        if (initialized) return;

        Files.createDirectories(CA_DIR);

        boolean rootExists = Files.exists(ROOT_KEY) && Files.exists(ROOT_CERT);
        boolean orgExists  = Files.exists(ORG_KEY)  && Files.exists(ORG_CERT);
        boolean voterExists= Files.exists(VOTER_KEY)&& Files.exists(VOTER_CERT);

        if (rootExists && orgExists && voterExists) {
            rootPriv = readPrivateKeyPem(ROOT_KEY);
            rootCert = readCertPem(ROOT_CERT);

            orgPriv  = readPrivateKeyPem(ORG_KEY);
            orgCert  = readCertPem(ORG_CERT);

            voterPriv= readPrivateKeyPem(VOTER_KEY);
            voterCert= readCertPem(VOTER_CERT);

        } else {
            KeyPair rootKP = KeyPairService.generateRSAKeyPair();
            rootCert = CertificateService.createRootCA(ROOT_DN, rootKP);
            rootPriv = rootKP.getPrivate();

            KeyPair orgKP = KeyPairService.generateRSAKeyPair();
            orgCert = CertificateService.createSubCA(ROOT_DN, rootPriv, rootKP.getPublic(), ORG_DN, orgKP);
            orgPriv = orgKP.getPrivate();

            KeyPair voterKP = KeyPairService.generateRSAKeyPair();
            voterCert = CertificateService.createSubCA(ROOT_DN, rootPriv, rootKP.getPublic(), VOTER_DN, voterKP);
            voterPriv = voterKP.getPrivate();

            writePrivateKeyPem(ROOT_KEY, rootPriv);
            writeCertPem(ROOT_CERT, rootCert);

            writePrivateKeyPem(ORG_KEY, orgPriv);
            writeCertPem(ORG_CERT, orgCert);

            writePrivateKeyPem(VOTER_KEY, voterPriv);
            writeCertPem(VOTER_CERT, voterCert);
        }

        initialized = true;
    }


    private static void writePrivateKeyPem(Path path, PrivateKey key) throws Exception {
        try (Writer w = Files.newBufferedWriter(path);
             JcaPEMWriter pem = new JcaPEMWriter(w)) {
            pem.writeObject(key);
        }
    }

    private static void writeCertPem(Path path, X509Certificate cert) throws Exception {
        try (Writer w = Files.newBufferedWriter(path);
             JcaPEMWriter pem = new JcaPEMWriter(w)) {
            pem.writeObject(cert);
        }
    }

    private static PrivateKey readPrivateKeyPem(Path path) throws Exception {
        try (Reader r = Files.newBufferedReader(path);
             PEMParser parser = new PEMParser(r)) {

            Object obj = parser.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider("BC");

            if (obj instanceof PEMKeyPair kp) {
                return conv.getKeyPair(kp).getPrivate();
            }
            if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                return conv.getPrivateKey(pki);
            }
            throw new IllegalStateException("Nepoznat format private key PEM: " + obj);
        }
    }

    private static X509Certificate readCertPem(Path path) throws Exception {
        try (Reader r = Files.newBufferedReader(path);
             PEMParser parser = new PEMParser(r)) {

            Object obj = parser.readObject();
            if (!(obj instanceof X509CertificateHolder holder)) {
                throw new IllegalStateException("Nepoznat format cert PEM: " + obj);
            }
            return new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(holder);
        }
    }
}
