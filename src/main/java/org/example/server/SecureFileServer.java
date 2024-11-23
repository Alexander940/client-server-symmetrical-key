package org.example.server;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

public class SecureFileServer {
    public static void main(String[] args) throws Exception {
        int port = 12345; // Puerto donde escucha el servidor
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Servidor esperando conexiones en el puerto " + port);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado.");

            try {
                // Establecer Diffie-Hellman para negociar la clave
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
                keyPairGenerator.initialize(2048);
                KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();

                // Enviar la clave pública al cliente
                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                out.writeObject(serverKeyPair.getPublic());
                out.flush();

                // Recibir la clave pública del cliente
                ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
                PublicKey clientPublicKey = (PublicKey) in.readObject();

                // Generar la clave secreta compartida
                KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                keyAgreement.init(serverKeyPair.getPrivate());
                keyAgreement.doPhase(clientPublicKey, true);
                byte[] sharedSecret = keyAgreement.generateSecret();

                // Derivar una clave AES de 256 bits de la clave compartida
                byte[] aesKeyBytes = Arrays.copyOf(sharedSecret, 32);
                SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
                System.out.println("Clave AES derivada por el servidor: " + Arrays.toString(aesKeyBytes));

                // Configurar cifrado AES
                Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

                // Recibir y descifrar archivo
                FileOutputStream fos = new FileOutputStream("archivo_recibido.txt");
                CipherInputStream cis = new CipherInputStream(clientSocket.getInputStream(), aesCipher);
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
                fos.close();
                System.out.println("Archivo recibido y descifrado.");

                // Calcular hash SHA-256 del archivo recibido
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                FileInputStream fis = new FileInputStream("archivo_recibido.txt");
                while ((bytesRead = fis.read(buffer)) != -1) {
                    sha256.update(buffer, 0, bytesRead);
                }
                fis.close();
                byte[] fileHash = sha256.digest();
                System.out.println("Hash calculado por el servidor: " + Arrays.toString(fileHash));

                // Enviar hash al cliente
                out.writeObject(fileHash);
                out.flush();
                System.out.println("Hash enviado al cliente.");
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                clientSocket.close();
                System.out.println("Conexión cerrada. Esperando un nuevo cliente...");
            }
        }
    }
}
