package server;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

// Esta clase ahora implementa el almacenamiento seguro 
//de contraseñas mediante Hash (SHA-256) y Salt.

public class UserStore {

    public static class User {
        public final String username;
        public final String salt;         
        public final String passwordHash; 
        public final Role role;

        public User(String username, String salt, String passwordHash, Role role) {
            this.username = username;
            this.salt = salt;
            this.passwordHash = passwordHash;
            this.role = role;
        }
    }

    public enum Role {
        USER, ADMIN, AUDITOR
    }

    private final Map<String, User> users = new HashMap<>();

    public UserStore(String path) {
        load(path);
    }

    private String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Base64.getDecoder().decode(salt));
            byte[] hashedBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    private void load(String path) {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {

            String line;

            while ((line = br.readLine()) != null) {

                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                String[] parts = line.split(":");
                
                // MODIFICADO: Ahora esperamos 4 partes (usuario:salt:hash:rol)
                if (parts.length != 4) continue;

                String username = parts[0].trim();
                String salt = parts[1].trim();
                String hash = parts[2].trim();
                Role role = Role.valueOf(parts[3].trim().toUpperCase());

                users.put(username, new User(username, salt, hash, role));
            }

        } catch (IOException e) {
            System.err.println("Error leyendo users.txt: " + e);
        }
    }

    public Optional<User> authenticate(String username, String password) {

        User u = users.get(username);
        if (u == null) return Optional.empty();
        
        String computedHash = hashPassword(password, u.salt);

        if (u.passwordHash.equals(computedHash)) {
            return Optional.of(u);
        }

        return Optional.empty();
    }
}