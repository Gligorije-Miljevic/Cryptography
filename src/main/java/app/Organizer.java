package app;

public class Organizer extends User{
    private final String orgName;
    private final String id;

    public Organizer(String orgName,String id,String password) {
        super(password);
        this.orgName = orgName;
        this.id = id;
    }

    public String getOrgName() {
        return orgName;
    }

    @Override
    public String toString() {
        return "Ime organizacije: "+orgName+", identifikacioni broj: "+id;
    }
    @Override
    public String getCertificateIdentity()
    {
        return "CN="+id+", OU=ORGANIZER, O=eVoting";
    }
    @Override
    public String getStorageName()
    {
        return id;
    }
}
