package model;

import java.io.Serializable;

public class VoteEnvelope implements Serializable {
    public byte[] ciphertext;
    public byte[] iv;
    public byte[] encAesKey;
    public byte[] signature;
    public String voterId;
    public byte[] receipt;
}
