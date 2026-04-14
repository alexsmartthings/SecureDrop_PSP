import protocol.Protocol;
import util.IOUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

/*
=========================================================
CLIENTMAIN
=========================================================

Esta clase:

- Se conecta al servidor.
- Envía comandos.
- Muestra respuestas.

Ahora mismo usa Socket normal (SIN cifrado).
En la versión segura habrá que usar TLS.
*/

public class ClientMain {

    public static void main(String[] args) {

        System.out.println("=== SecureDrop Client v1 (INSEGURA) ===");

        Scanner sc = new Scanner(System.in);

        System.out.print("Servidor (host) [localhost]: ");
        String host = sc.nextLine().trim();
        if (host.isEmpty()) host = "localhost";

        System.out.print("Puerto [15000]: ");
        String portStr = sc.nextLine().trim();
        int port = portStr.isEmpty() ? 15000 : Integer.parseInt(portStr);


        // Configuramos la ruta al truststore y su contraseña
        System.setProperty("javax.net.ssl.trustStore", "ssl/client_truststore.p12");
        System.setProperty("javax.net.ssl.trustStorePassword", "123456");

        try (
                // =====================================================
                // TODO 1:
                // Cambiar Socket por SSLSocket.
                // Esto activará comunicación cifrada (TLS).
                // =====================================================

                Socket socket = javax.net.ssl.SSLSocketFactory.getDefault().createSocket(host, port);

                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

                PrintWriter out = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true)
        ) {

            System.out.println("SERVER> " + in.readLine());

            // LOGIN
            System.out.print("Usuario: ");
            String user = sc.nextLine().trim();

            System.out.print("Contraseña: ");
            String pass = sc.nextLine().trim();

            out.println("LOGIN " + user + " " + pass);

            String resp = in.readLine();
            System.out.println("SERVER> " + resp);

            if (resp == null || !resp.startsWith(Protocol.OK)) {
                System.out.println("Login fallido.");
                return;
            }

            // MENÚ
            while (true) {

                System.out.println("\n--- Menú ---");
                System.out.println("1) Enviar mensaje");
                System.out.println("2) Listar mis mensajes");
                System.out.println("3) (Admin) Listar TODOS los mensajes");
                System.out.println("0) Salir");
                System.out.print("> ");

                String opt = sc.nextLine().trim();

                if ("1".equals(opt)) {

                    System.out.println("Escribe el mensaje:");
                    String msg = sc.nextLine();

                    // =====================================================
                    // TODO 2:
                    // Podría añadirse validación de tamaño aquí también
                    // antes de enviarlo al servidor.
                    // =====================================================

                    try {
                        // Extraer clave pública del servidor desde el truststore
                        KeyStore ts = KeyStore.getInstance("PKCS12");
                        try (FileInputStream fis = new FileInputStream("ssl/client_truststore.p12")) {
                            ts.load(fis, "123456".toCharArray());
                        }
                        PublicKey serverPublicKey = ts.getCertificate("servidor").getPublicKey();

                        // Generar clave AES temporal (128 bits) para este mensaje
                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(128);
                        SecretKey aesKey = keyGen.generateKey();

                        // Cifrar el mensaje con la clave AES
                        Cipher aesCipher = Cipher.getInstance("AES");
                        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                        byte[] encryptedMsgBytes = aesCipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
                        String encryptedMsgBase64 = Base64.getEncoder().encodeToString(encryptedMsgBytes);

                        // Cifrar la clave AES con la clave pública RSA del servidor
                        Cipher rsaCipher = Cipher.getInstance("RSA");
                        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
                        byte[] encryptedKeyBytes = rsaCipher.doFinal(aesKey.getEncoded());
                        String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedKeyBytes);

                        // Enviar al servidor: Comando + Clave Cifrada + Mensaje Cifrado
                        out.println("SEND " + encryptedKeyBase64 + " " + encryptedMsgBase64);
                        System.out.println("SERVER> " + in.readLine());

                    } catch (Exception e) {
                        System.out.println("Error al cifrar el mensaje: " + e.getMessage());
                    }

                } else if ("2".equals(opt)) {

                    out.println("LIST");
                    IOUtil.readMultilineUntilEnd(in);

                } else if ("3".equals(opt)) {

                    out.println("LIST_ALL");
                    IOUtil.readMultilineUntilEnd(in);

                } else if ("0".equals(opt)) {

                    out.println("QUIT");
                    System.out.println("SERVER> " + in.readLine());
                    break;

                } else {
                    System.out.println("Opción no válida.");
                }
            }

        } catch (Exception e) {

            // =====================================================
            // TODO 3:
            // En versión segura no mostrar detalles técnicos.
            // Mostrar solo mensaje genérico.
            // =====================================================

            System.err.println("Error cliente: " + e);
            e.printStackTrace();
        }
    }
}
