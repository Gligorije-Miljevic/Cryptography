package model;

import crypto.HmacKeyStore;
import crypto.VoteCrypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Function;

public class Voting implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String id;
    private final String title;
    private final String description;
    private final String organizerId;
    private final LocalDateTime startTime;
    private final LocalDateTime endTime;
    private final List<String> candidates;

    private final List<VoteEnvelope> votes;

    private enum VotingStatus { NOT_STARTED, ACTIVE, FINISHED }

    public Voting(String organizerId, String title, String description,
                  LocalDateTime startTime, LocalDateTime endTime, List<String> candidates) {

        if (organizerId == null || organizerId.isBlank()) throw new IllegalArgumentException();
        if (title == null || title.isBlank()) throw new IllegalArgumentException();
        if (description == null || description.isBlank()) throw new IllegalArgumentException();
        if (startTime == null || endTime == null) throw new IllegalArgumentException();
        if (!startTime.isBefore(endTime)) throw new IllegalArgumentException();
        if (candidates == null || candidates.size() < 2 || candidates.size() > 5) throw new IllegalArgumentException();

        this.organizerId = organizerId;
        this.id = UUID.randomUUID().toString();
        this.title = title;
        this.description = description;
        this.startTime = startTime;
        this.endTime = endTime;
        this.candidates = new ArrayList<>(candidates);
        this.votes = new ArrayList<>();
    }

    private Voting(String id, String organizerId, String title, String description,
                   LocalDateTime startTime, LocalDateTime endTime, List<String> candidates,
                   List<VoteEnvelope> votes) {
        this.id = id;
        this.organizerId = organizerId;
        this.title = title;
        this.description = description;
        this.startTime = startTime;
        this.endTime = endTime;
        this.candidates = new ArrayList<>(candidates);
        this.votes = new ArrayList<>(votes);
    }

    private VotingStatus getStatus() {
        LocalDateTime now = LocalDateTime.now();
        if (now.isBefore(startTime)) return VotingStatus.NOT_STARTED;
        if (now.isAfter(endTime)) return VotingStatus.FINISHED;
        return VotingStatus.ACTIVE;
    }

    public boolean isActive() { return getStatus() == VotingStatus.ACTIVE; }
    public boolean isFinished() { return getStatus() == VotingStatus.FINISHED; }
    public List<String> getCandidates() { return candidates; }
    public String getId() { return id; }
    public String getOrganizerId() { return organizerId; }

    public boolean hasVoted(String voterId) {
        for (VoteEnvelope v : votes) if (v.voterId.equals(voterId)) return true;
        return false;
    }

    private byte[] metaBytes() {
        StringBuilder sb = new StringBuilder();
        sb.append("id=").append(id).append("\n");
        sb.append("organizerId=").append(organizerId).append("\n");
        sb.append("title=").append(title).append("\n");
        sb.append("description=").append(description).append("\n");
        sb.append("start=").append(startTime).append("\n");
        sb.append("end=").append(endTime).append("\n");
        for (String c : candidates) sb.append("cand=").append(c).append("\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static boolean constEq(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= (a[i] ^ b[i]);
        return r == 0;
    }

    private static byte[] receiptBytes(String votingId, VoteEnvelope ve) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update(votingId.getBytes(StandardCharsets.UTF_8));
        md.update((byte) 0x00);
        md.update(ve.voterId.getBytes(StandardCharsets.UTF_8));
        md.update((byte) 0x00);
        md.update(ve.iv);
        md.update(ve.ciphertext);
        md.update(ve.encAesKey);
        md.update(ve.signature);
        return md.digest();
    }

    public String castVoteCrypto(String voterId, String option, PublicKey organizerPub, PrivateKey voterPriv) throws Exception {

        SecretKey aesKey = VoteCrypto.genAesKey();
        VoteCrypto.AesGcmResult enc = VoteCrypto.aesGcmEncrypt(option.getBytes(StandardCharsets.UTF_8), aesKey);
        byte[] encAesKey = VoteCrypto.rsaOaepEncrypt(aesKey.getEncoded(), organizerPub);

        byte[] signature = VoteCrypto.sign(enc.ct, voterPriv);

        VoteEnvelope ve = new VoteEnvelope();
        ve.voterId = voterId;
        ve.iv = enc.iv;
        ve.ciphertext = enc.ct;
        ve.encAesKey = encAesKey;
        ve.signature = signature;

        ve.receipt = receiptBytes(this.id, ve);

        votes.add(ve);

        return Base64.getEncoder().encodeToString(ve.receipt);
    }

    public boolean verifyVoteReceipt(String voterId, String receiptB64, PublicKey voterPub) throws Exception {
        byte[] expected = Base64.getDecoder().decode(receiptB64);
        for (VoteEnvelope ve : votes) {
            if (!ve.voterId.equals(voterId)) continue;

            byte[] rec = receiptBytes(this.id, ve);
            if (!constEq(rec, expected)) return false;

            if (!VoteCrypto.verify(ve.ciphertext, ve.signature, voterPub)) return false;

            return true;
        }
        return false;
    }

    public Map<String, Integer> countVotesCrypto(PrivateKey organizerPriv, Function<String, PublicKey> voterPubResolver) throws Exception {

        if (getStatus() != VotingStatus.FINISHED) throw new IllegalStateException();

        Map<String, Integer> result = new LinkedHashMap<>();
        for (String c : candidates) result.put(c, 0);

        for (VoteEnvelope ve : votes) {

            PublicKey voterPub = voterPubResolver.apply(ve.voterId);
            if (voterPub == null) continue;//throw new IllegalStateException("Ne postoji voter pubkey: " + ve.voterId);

            if (!VoteCrypto.verify(ve.ciphertext, ve.signature, voterPub))
                continue;//throw new IllegalStateException("Nevalidan potpis glasa: " + ve.voterId);

            byte[] aesRaw = VoteCrypto.rsaOaepDecrypt(ve.encAesKey, organizerPriv);
            SecretKey aes = new SecretKeySpec(aesRaw, "AES");

            byte[] plain = VoteCrypto.aesGcmDecrypt(ve.iv, ve.ciphertext, aes);
            String opt = new String(plain, StandardCharsets.UTF_8);

            if (!result.containsKey(opt))
                throw new IllegalStateException("Nepoznata opcija u glasu: " + opt);

            result.put(opt, result.get(opt) + 1);
        }
        return result;
    }

    public boolean verifyVotePresence(String voterId) {
        for (VoteEnvelope ve : votes) if (ve.voterId.equals(voterId)) return true;
        return false;
    }

    public void exportSignedResults(Path dir, Map<String, Integer> results, PrivateKey organizerPriv) throws Exception {
        Files.createDirectories(dir);

        StringBuilder sb = new StringBuilder();
        sb.append("ID: ").append(id).append("\n");
        sb.append("Organizator: ").append(organizerId).append("\n");
        sb.append("Naslov: ").append(title).append("\n");
        sb.append("Opis: ").append(description).append("\n");
        sb.append("Pocetak: ").append(startTime).append("\n");
        sb.append("Kraj: ").append(endTime).append("\n");
        sb.append("Status: ").append(getStatus()).append("\n\n");
        results.forEach((k, v) -> sb.append(k).append(" = ").append(v).append("\n"));

        byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] sig = VoteCrypto.sign(data, organizerPriv);

        Files.writeString(dir.resolve("results_" + id + ".txt"), sb.toString());
        Files.write(dir.resolve("results_" + id + ".sig"), sig);
    }

    public void saveVotingToFile(Path directory) throws Exception {
        Files.createDirectories(directory);

        VotingMeta meta = new VotingMeta();
        meta.id = id;
        meta.organizerId = organizerId;
        meta.title = title;
        meta.description = description;
        meta.startTime = startTime;
        meta.endTime = endTime;
        meta.candidates = new ArrayList<>(candidates);

        byte[] hmacKey = HmacKeyStore.getOrCreate();
        meta.hmac = VoteCrypto.hmacSha256(hmacKey, metaBytes());

        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(directory.resolve(id + ".meta")))) {
            oos.writeObject(meta);
        }

        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(directory.resolve(id + ".votes")))) {
            oos.writeObject(new ArrayList<>(votes));
        }
    }

    public static Voting loadFromFiles(Path directory, String id) throws Exception {
        VotingMeta meta;
        List<VoteEnvelope> votes;

        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(directory.resolve(id + ".meta")))) {
            meta = (VotingMeta) ois.readObject();
        }
        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(directory.resolve(id + ".votes")))) {
            votes = (List<VoteEnvelope>) ois.readObject();
        }

        Voting v = new Voting(meta.id, meta.organizerId, meta.title, meta.description,
                meta.startTime, meta.endTime, meta.candidates, votes);

        byte[] hmacKey = HmacKeyStore.getOrCreate();
        byte[] expected = VoteCrypto.hmacSha256(hmacKey, v.metaBytes());

        if (!constEq(expected, meta.hmac))
            throw new IllegalStateException("HMAC metapodataka ne odgovara (integritet narusen)");

        return v;
    }

    @Override
    public String toString() {
        return "Voting[id=" + id + ", title=" + title + ", status=" + getStatus() + ", organizer=" + organizerId + "]";
    }
}
