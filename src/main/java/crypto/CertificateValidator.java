package crypto;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.nio.file.Path;

public class CertificateValidator {

    public static void validateUserCert(
            X509Certificate userCert,
            X509Certificate issuerCert,
            Path issuerCrlFile
    ) throws Exception {
        userCert.checkValidity();
        PublicKey issuerPub = issuerCert.getPublicKey();
        userCert.verify(issuerPub);
        BigInteger serial = userCert.getSerialNumber();
        SimpleCRL crl = new SimpleCRL(issuerCrlFile);
        if (crl.isRevoked(serial)) {
            throw new IllegalStateException("Sertifikat je povučen (CRL).");
        }
    }
}
