package model;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

public class VotingMeta implements Serializable {
    @Serial private static final long serialVersionUID = 1L;

    public String id;
    public String title;
    public String description;
    public String organizerId;
    public LocalDateTime startTime;
    public LocalDateTime endTime;
    public List<String> candidates;

    public byte[] hmac;
}
