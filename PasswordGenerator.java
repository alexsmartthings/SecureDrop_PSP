import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class PasswordGenerator {
    public static void main(String[] args) throws Exception {
        // Ejecuta esto para generar las líneas de tu users.txt
        generarUsuario("admin", "admin123", "ADMIN");
        generarUsuario("juan", "1234", "USER");
        generarUsuario("maria", "abcd", "USER");
        generarUsuario("auditor", "audit", "AUDITOR");
    }

    private static void generarUsuario(String user, String pass, String rol) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        String salt = Base64.getEncoder().encodeToString(saltBytes);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(saltBytes);
        byte[] hashedBytes = md.digest(pass.getBytes(StandardCharsets.UTF_8));
        String hash = Base64.getEncoder().encodeToString(hashedBytes);

        System.out.println(user + ":" + salt + ":" + hash + ":" + rol);
    }
}