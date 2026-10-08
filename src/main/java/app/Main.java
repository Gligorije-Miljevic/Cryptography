package app;

import crypto.*;
import model.UserCredentials;
import model.Voting;
import storage.PrivateKeyStorage;
import storage.UserStorage;
import storage.VotingStorage;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Function;

public class Main {

    static Scanner sc = new Scanner(System.in);

    private static void revokeUserCertificate(User user) {
        try {
            String serial = user.getCertificateSerial();
            if (serial == null) {
                System.out.println("Nema serijskog broja sertifikata.");
                return;
            }

            Path crlPath;

            if (user instanceof Voter) {
                crlPath = Path.of("storage/crl/voter.crl");
            } else {
                crlPath = Path.of("storage/crl/organizer.crl");
            }

            SimpleCRL crl = new SimpleCRL(crlPath);
            crl.revoke(new java.math.BigInteger(serial));

            System.out.println("Sertifikat je povucen i dodat u CRL.");

        } catch (Exception e) {
            System.out.println("Greska pri povlacenju sertifikata: " + e.getMessage());
        }
    }


    public static void saveCertificateToPem(X509Certificate cert, String filename) throws Exception {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(filename))) {
            writer.writeObject(cert);
        }
    }

    public static X509Certificate loadCertificate(String path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = new FileInputStream(path)) {
            return (X509Certificate) cf.generateCertificate(in);
        }
    }

    public static User registracija() {
        char unos;
        do {
            unos = sc.next().charAt(0);
        } while (unos != 'G' && unos != 'O');

        if (unos == 'G') {
            System.out.println("===Registracija glasaca na sistem===");
            System.out.println("Unesite vase ime:");
            String name = sc.next();
            System.out.println("Unesite vase prezime:");
            String surname = sc.next();
            System.out.println("Unesite vase korisnicko ime:");
            String username = sc.next();
            System.out.println("Unesite lozinku:");
            String password = sc.next();
            Voter v = new Voter(name, surname, username, password);
            v.setPlainPassword(password);
            return v;
        } else {
            System.out.println("===Registracija organizatora na sistem===");
            System.out.println("Unesite ime vase organizacije:");
            String orgName = sc.next();
            System.out.println("Unesite identifikacioni broj:");
            String id = sc.next();
            System.out.println("Unesite lozinku:");
            String password = sc.next();
            Organizer o1 = new Organizer(orgName, id, password);
            o1.setPlainPassword(password);
            return o1;
        }
    }

    public static String extractCN(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.startsWith("CN=")) return part.substring(3);
        }
        return null;
    }

    private static String readNonEmptyLine() {
        String s;
        do {
            s = sc.nextLine();
        } while (s != null && s.trim().isEmpty());
        return s == null ? "" : s.trim();
    }

    private static List<Voting> getActiveVotings(Path votingsDir) throws Exception {
        List<Voting> all = VotingStorage.getAllVotings(votingsDir);
        List<Voting> active = new ArrayList<>();
        for (Voting v : all) {
            if (v.toString().contains("status=ACTIVE")) active.add(v);
        }
        return active;
    }
    private static PublicKey loadUserPublicKey(String userId) throws Exception {
        X509Certificate cert = loadCertificate("storage/certs/" + userId + ".pem");
        return cert.getPublicKey();
    }

    public static void main(String[] args) {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        Path votingsDir = Paths.get("storage", "votings");
        Map<String, User> users;
        try {
            users = UserStorage.loadAllUsers();
        } catch (Exception e) {
            users = new HashMap<>();
        }
        User u1 = null;
        System.out.println("Unos opcije za Registraciju [R] / Prijavu [P]");
        char unos;
        do {
            String line = readNonEmptyLine();
            unos = line.isEmpty() ? '\0' : line.charAt(0);
        } while (unos != 'P' && unos != 'R');
        // POCETAK //
        if (unos == 'R') {
            System.out.println("===Registracija na sistem===");
            System.out.println("Unesite da li ste Glasac [G] / Organizator [O]");
            u1 = registracija();
            try {
                KeyPair kp = KeyPairService.generateRSAKeyPair();
                X509Certificate cert;

                if (u1 instanceof Voter) {
                    cert = CertificateService.issueVoterCert(CAStore.getVoterCaDn(), CAStore.getVoterCaPrivateKey(),
                            u1.getCertificateIdentity(), kp);
                } else {
                    cert = CertificateService.issueOrganizerCert(CAStore.getOrgCaDn(),
                            CAStore.getOrgCaPrivateKey(), u1.getCertificateIdentity(), kp);
                }
                u1.setCertificateSerial(cert.getSerialNumber().toString());
                u1.setCredentials(new UserCredentials(kp.getPublic(), kp.getPrivate(), cert));

                Files.createDirectories(Path.of("storage/keys"));
                PrivateKeyStorage.saveEncryptedPrivateKey(
                        kp.getPrivate(),
                        u1.getPlainPassword(),
                        "storage/keys/" + u1.getStorageName() + ".key"
                );

                u1.clearPlainPassword();

                Files.createDirectories(Path.of("storage/certs"));
                saveCertificateToPem(cert, "storage/certs/" + u1.getStorageName() + ".pem");

                UserStorage.saveUser(u1);
                System.out.println("Registracija uspjesna.");
                return;

            } catch (Exception e) {
                System.out.println("Greska pri registraciji");
                e.printStackTrace();
                return;
            }
//PRIJAVAAA
            } else {
            System.out.println("===Prijava na sistem===");
            System.out.print("Unesite putanju do vaseg digitalnog sertifikata: ");
            String certPath = readNonEmptyLine();
            try {
                X509Certificate cert = loadCertificate(certPath);
                cert.checkValidity();
                String cn = extractCN(cert);
                if (cn == null) throw new Exception();

                u1 = users.get(cn);
                if (u1 == null) throw new Exception();


                if (u1 instanceof Voter) {
                    CertificateValidator.validateUserCert(
                            cert,
                            CAStore.getVoterCaCert(),
                            Path.of("storage/crl/voter.crl")
                    );
                } else {
                    CertificateValidator.validateUserCert(
                            cert,
                            CAStore.getOrgCaCert(),
                            Path.of("storage/crl/organizer.crl")
                    );
                }
                System.out.print("Unesite korisnicko ime: ");
                String username = readNonEmptyLine();

                if (!username.equals(cn)) {
                    System.out.println("Korisnicko ime se ne poklapa sa sertifikatom.");
                    return;
                }
                while (true) {
                    System.out.print("Unesite lozinku: ");
                    String pass = readNonEmptyLine();

                    if (u1.verifyPassword(pass)) {
                        u1.resetFailedLoginAttempts();
                        System.out.println("Uspjesna prijava");
                        break;
                    } else {
                        u1.incFailedLoginAttempts();
                        System.out.println("Pogresna lozinka (" + u1.getFailedLoginAttempts() + "/3)");

                        if (u1.getFailedLoginAttempts() >= 3) {
                            revokeUserCertificate(u1);
                            System.out.println("Sertifikat je povucen.");
                            return;
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Neispravan ili nevazeci sertifikat.");
                return;
            }
        }

        if (u1 instanceof Organizer) {

            System.out.println("===Organizator===");
            try {
                VotingStorage.printAllVotings(votingsDir);
            } catch (Exception ignored) {}

            System.out.println("Kreiranje novog glasanja [N], Brojanje glasova [B]");
            do {
                unos = sc.next().charAt(0);
            } while (unos != 'N' && unos != 'B');
            sc.nextLine();

            if (unos == 'N') {
                DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm");

                System.out.println("===Kreiranje novog glasanja===");
                System.out.println("Unesite naslov glasanja: ");
                String title = readNonEmptyLine();
                System.out.println("Unesite opis: ");
                String description = readNonEmptyLine();

                System.out.println("Unesite pocetak glasanja: (dd-MM-yyyy HH:mm)");
                LocalDateTime startTime = LocalDateTime.parse(readNonEmptyLine(), dtf);

                System.out.println("Unesite zavrsetak glasanja: (dd-MM-yyyy HH:mm)");
                LocalDateTime endTime = LocalDateTime.parse(readNonEmptyLine(), dtf);

                if (!startTime.isBefore(endTime)) {
                    System.out.println("Kraj glasanja mora biti nakon pocetka");
                    return;
                }

                System.out.println("Unesite opcije za glasanje: (2-5 opcija)");
                System.out.println("Unesite X za kraj unosa.");

                List<String> candidates = new ArrayList<>();
                while (candidates.size() < 5) {
                    System.out.println("Opcija " + (candidates.size() + 1) + ":");
                    String input = readNonEmptyLine();
                    if (input.equalsIgnoreCase("X")) break;
                    if (input.isEmpty()) continue;
                    candidates.add(input);
                }

                if (candidates.size() < 2) {
                    System.out.println("Morate unijeti bar 2 opcije.");
                    return;
                }

                String organizerID = u1.getStorageName();
                Voting v1 = new Voting(organizerID, title, description, startTime, endTime, candidates);

                try {
                    v1.saveVotingToFile(votingsDir);
                    System.out.println("Glasanje sacuvano. ID=" + v1.getId());
                } catch (Exception e) {
                    System.out.println("Greska pri cuvanju glasanja: " + e.getMessage());
                }
            } else {
                List<Voting> all;
                try {
                    all = VotingStorage.getAllVotings(votingsDir);
                } catch (Exception e) {
                    System.out.println("Ne mogu ucitati glasanja.");
                    return;
                }
                if (all.isEmpty()) {
                    System.out.println("Nema snimljenih glasanja.");
                    return;
                }
                for (int i = 0; i < all.size(); i++) {
                    System.out.println((i + 1) + ") " + all.get(i));
                }
                System.out.println("Izaberite redni broj glasanja za brojanje: ");
                int idx;
                try {
                    idx = Integer.parseInt(readNonEmptyLine()) - 1;
                } catch (Exception e) {
                    System.out.println("Neispravan izbor.");
                    return;
                }
                if (idx < 0 || idx >= all.size()) {
                    System.out.println("Neispravan izbor.");
                    return;
                }
                Voting selected = all.get(idx);
                if (!selected.getOrganizerId().equals(u1.getStorageName())) {
                    System.out.println("Ne mozete brojati glasanje koje niste kreirali.");
                    return;
                }

                System.out.println("Unesite lozinku organizatora (za ucitavanje privatnog kljuca):");
                String orgPass = readNonEmptyLine();

                try {
                    PrivateKey organizerPriv = PrivateKeyStorage.loadEncryptedPrivateKey(
                            "storage/keys/" + u1.getStorageName() + ".key",
                            orgPass
                    );

                    //Map<String, User> usersNow = UserStorage.loadAllUsers();

                    Function<String, PublicKey> voterResolver = voterId -> {
                        try {
                            X509Certificate cert =
                                    loadCertificate("storage/certs/" + voterId + ".pem");

                            CertificateValidator.validateUserCert(
                                    cert,
                                    CAStore.getVoterCaCert(),
                                    Path.of("storage/crl/voter.crl")
                            );

                            return cert.getPublicKey();
                        } catch (Exception e) {
                            return null;
                        }
                    };


                    Map<String, Integer> res = selected.countVotesCrypto(organizerPriv, voterResolver);
                    System.out.println("===Rezultati===");
                    res.forEach((k, v) -> System.out.println(k + " = " + v));

                    selected.exportSignedResults(Paths.get("storage", "results"), res, organizerPriv);
                    System.out.println("Izvjestaj sacuvan");

                } catch (Exception e) {
                    System.out.println("Brojanje nije moguce: " + e.getMessage());
                }
            }

        } else if (u1 instanceof Voter) {

            System.out.println("===Glasac===");

            List<Voting> active = new ArrayList<>();
            try {
                List<Voting> all = VotingStorage.getAllVotings(votingsDir);

                for (Voting v : all) {
                    if (v.isActive()) {
                        active.add(v);
                    }
                }

            } catch (Exception e) {
                System.out.println("Ne mogu ucitati glasanja.");
                return;
            }

            if (active.isEmpty()) {
                System.out.println("Nema dostupnih glasanja.");
                return;
            }

            for (int i = 0; i < active.size(); i++) {
                System.out.println((i + 1) + ") " + active.get(i));
            }


            System.out.println("Izaberite redni broj glasanja: ");
            int idx;
            try {
                idx = Integer.parseInt(readNonEmptyLine()) - 1;
            } catch (Exception e) {
                System.out.println("Neispravan izbor.");
                return;
            }
            if (idx < 0 || idx >= active.size()) {
                System.out.println("Neispravan izbor.");
                return;
            }
            Voting selected = active.get(idx);
            System.out.println("Opcija: [G]lasaj ili [V]erifikuj receipt");
            char c = readNonEmptyLine().toUpperCase().charAt(0);
            if (c == 'V') {
                System.out.print("Unesite receipt: ");
                String receipt = readNonEmptyLine();

                try {
                    PublicKey voterPub = loadUserPublicKey(u1.getStorageName());
                    boolean ok = selected.verifyVoteReceipt(u1.getStorageName(), receipt, voterPub);

                    System.out.println(
                            ok
                                    ? "Receipt je validan. Glas je zabiljezen."
                                    : "Receipt nije validan ili glas ne postoji."
                    );
                } catch (Exception e) {
                    System.out.println("Greska pri verifikaciji receipta.");
                }
                return;
            }


            if (selected.hasVoted(u1.getStorageName())) {
                System.out.println("Vec ste glasali na ovom glasanju.");
                return;
            }
            if (!selected.isActive() && selected.isFinished()) {
                System.out.println("Glasanje je zavrseno.");
                return;
            }else if (!selected.isActive() && !selected.isFinished()) {
                System.out.println("Glasanje jos nije aktivno.");
                return;
            }
            System.out.println("Opcije:");
            List<String> candidates = selected.getCandidates();
            for (int i = 0; i < candidates.size(); i++) {
                System.out.println((i + 1) + ") " + candidates.get(i));
            }
            System.out.println("Izaberite opciju: ");
            int opt;
            try {
                opt = Integer.parseInt(readNonEmptyLine()) - 1;
            } catch (Exception e) {
                System.out.println("Neispravan izbor.");
                return;
            }
            try {
                String orgId = selected.getOrganizerId();
                Map<String, User> usersNow = UserStorage.loadAllUsers();
                if (!usersNow.containsKey(orgId)) {
                    System.out.println("Ne mogu naci organizatora (user ne postoji): " + orgId);
                    return;
                }

                PublicKey organizerPub = loadUserPublicKey(orgId);

                System.out.println("Unesite lozinku glasača (za ucitavanje privatnog kljuca):");
                String voterPass = readNonEmptyLine();

                PrivateKey voterPriv = PrivateKeyStorage.loadEncryptedPrivateKey("storage/keys/" + u1.getStorageName() + ".key", voterPass);

                String chosenOption = selected.getCandidates().get(opt);

                String receipt = selected.castVoteCrypto(u1.getStorageName(), chosenOption, organizerPub, voterPriv);
                selected.saveVotingToFile(votingsDir);

                System.out.println("Vas glas je sacuvan.");
                System.out.println("Potvrda (receipt): " + receipt);
                System.out.println("Sacuvajte ovaj kod za kasniju provjeru.");

                if (selected.verifyVotePresence(u1.getStorageName())) {
                    System.out.println("Vas glas je uspjesno sacuvan.");
                } else {
                    System.out.println("Vas glas nije pronadjen.");
                }

            } catch (Exception e) {
                System.out.println("Neuspjesno glasanje: " + e);
            }
        }
    }
}
