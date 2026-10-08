package storage;

import app.User;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class UserStorage {
    private static final String USER_DIR = "storage/users";
    public static void saveUser(User user){
        File dir = new File(USER_DIR);
        dir.mkdirs();
        File file = new File(dir,user.getStorageName()+".user");
        try(ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(file))){
            out.writeObject(user);
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    public static Map<String,User> loadAllUsers() throws IOException, ClassNotFoundException
    {
        Map<String,User> users = new HashMap<>();
        File dir = new File(USER_DIR);
        if(!dir.exists())return users;
        for(File file : dir.listFiles())
        {
            try(ObjectInputStream in = new ObjectInputStream(new FileInputStream(file))){
                User u = (User) in.readObject();
                users.put(u.getStorageName(),u);
            }
        }
        return users;
    }
}
