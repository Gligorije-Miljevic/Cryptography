package app;

public class Voter extends User{
    private final String name;
    private final String surname;
    private final String username;

    public Voter(String name,String surname,String username,String password) {
        super(password);
        this.name = name;
        this.username = username;
        this.surname = surname;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public String toString() {
        return "Ime: "+name+", prezime: "+surname+", korisnicko ime: "+username;
    }
    @Override
    public String getCertificateIdentity()
    {
        return "CN="+username+", OU=VOTER, O=eVoting";
    }
    @Override
    public String getStorageName()
    {
        return username;
    }
}
