package storage;

import model.Voting;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class VotingStorage {

    public static List<Voting> getAllVotings(Path directory) throws Exception {
        List<Voting> all = new ArrayList<>();
        if (Files.notExists(directory)) return all;

        File[] metas = directory.toFile().listFiles((dir, name) -> name.endsWith(".meta"));
        if (metas == null) return all;

        for (File metaFile : metas) {
            String name = metaFile.getName();
            String id = name.substring(0, name.length() - ".meta".length());
            try {
                all.add(Voting.loadFromFiles(directory, id));
            } catch (Exception ignored) {
            }
        }

        return all;
    }

    public static Voting loadById(Path directory, String id) throws Exception {
        Path meta = directory.resolve(id + ".meta");
        Path votes = directory.resolve(id + ".votes");
        if (!Files.exists(meta) || !Files.exists(votes)) return null;
        return Voting.loadFromFiles(directory, id);
    }

    public static void printAllVotings(Path directory) throws Exception {
        for (Voting v : getAllVotings(directory)) System.out.println(v);
    }
}
