package app;

import crypto.PasswordUtils;
import model.*;

import java.io.Serializable;

public abstract class User implements Serializable {
    private final String passwordHash;
    private final byte[] salt;
    private transient UserCredentials credentials;
    private transient String plainPassword;
    private int failedLoginAttempts=0;
    public String certificateSerial;

    public void setCertificateSerial(String s){
        this.certificateSerial = s;
    }
    public String getCertificateSerial(){
        return certificateSerial;
    }
    public int getFailedLoginAttempts(){
        return failedLoginAttempts;
    }
    public void resetFailedLoginAttempts(){
        failedLoginAttempts = 0;
    }
    public void incFailedLoginAttempts(){
        failedLoginAttempts++;
    }

    public void setPlainPassword(String plainPassword) {
        this.plainPassword = plainPassword;
    }

    public String getPlainPassword() {
        return plainPassword;
    }

    public void clearPlainPassword() {
        this.plainPassword = null;
    }
    public User(String password) {
        try {
            this.salt = PasswordUtils.generateSalt();
            this.passwordHash = PasswordUtils.hashPassword(password, salt);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public boolean verifyPassword(String inputPassword) {
        try {
            String inputHash = PasswordUtils.hashPassword(inputPassword, salt);
            return inputHash.equals(passwordHash);
        } catch (Exception e) {
            return false;
        }
    }
    public void setCredentials(UserCredentials creds) {
        this.credentials = creds;
    }

    public UserCredentials getCredentials() {
        return credentials;
    }
    public abstract String getStorageName();

    public abstract String getCertificateIdentity();
}
