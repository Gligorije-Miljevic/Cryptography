package crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import model.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CertificateService {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    /*public static X509Certificate generateUserCertificate(String subjectDn, KeyPair keyPair) throws Exception {

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000);
        X500Name subject = new X500Name(subjectDn);
        X500Name issuer = subject;
        BigInteger serialNumber = BigInteger.valueOf(now);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, startDate, endDate, subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }*/
    private static X509Certificate buildCert(X500Name issuer, PrivateKey issuerKey, X500Name subject, PublicKey subjectPub,
            boolean isCA, KeyUsage keyUsage, ExtendedKeyUsage eku) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000);
        Date notAfter  = new Date(now + 365L * 24 * 60 * 60 * 1000);
        BigInteger serial = BigInteger.valueOf(now).add(BigInteger.valueOf((long)(Math.random()*100000)));
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, subjectPub);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));
        b.addExtension(Extension.keyUsage, true, keyUsage);
        if (eku != null) {
            b.addExtension(Extension.extendedKeyUsage, false, eku);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }
    public static X509Certificate createRootCA(String dn, KeyPair kp) throws Exception {
        X500Name name = new X500Name(dn);
        KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        return buildCert(name, kp.getPrivate(), name, kp.getPublic(), true, ku, null);
    }

    public static X509Certificate createSubCA(String issuerDn, PrivateKey rootKey, PublicKey rootPub, String subDn, KeyPair subKP) throws Exception {
        X500Name issuer = new X500Name(issuerDn);
        X500Name subject = new X500Name(subDn);
        KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        return buildCert(issuer, rootKey, subject, subKP.getPublic(), true, ku, null);
    }
    public static X509Certificate issueVoterCert(String caDn, PrivateKey caKey, String userDn, KeyPair userKP) throws Exception {
        X500Name issuer = new X500Name(caDn);
        X500Name subject = new X500Name(userDn);
        KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature);
        ExtendedKeyUsage eku = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
        return buildCert(issuer, caKey, subject, userKP.getPublic(), false, ku, eku);
    }

    public static X509Certificate issueOrganizerCert(String caDn, PrivateKey caKey, String userDn, KeyPair userKP) throws Exception {
        X500Name issuer = new X500Name(caDn);
        X500Name subject = new X500Name(userDn);
        KeyUsage ku = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature);
        ExtendedKeyUsage eku = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
        return buildCert(issuer, caKey, subject, userKP.getPublic(), false, ku, eku);
    }
}
