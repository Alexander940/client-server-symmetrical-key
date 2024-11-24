package org.example.server;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class SecureFileServer {
    public static void main(String[] args) {
        int port = 12345;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("\nServidor escuchando en el puerto " + port);

            while (true) {
                Socket client = serverSocket.accept();
                System.out.println("Cliente conectado: " + client.getInetAddress().getHostAddress());

                new Thread(() -> handleClient(client)).start();
            }
        } catch (IOException e) {
            System.err.println("Error en el servidor: " + e.getMessage());
        }
    }

    private static void handleClient(Socket client) {
        try (
                InputStream input = client.getInputStream();
                OutputStream output = client.getOutputStream()
        ) {
            // Generar las claves Diffie-Hellman
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Enviar la clave pública al cliente
            output.write(keyPair.getPublic().getEncoded());
            output.flush();

            // Recibir la clave pública del cliente
            byte[] clientPubKeyBytes = new byte[2048];
            int bytesRead = input.read(clientPubKeyBytes);
            PublicKey clientPubKey = KeyFactory.getInstance("DH")
                    .generatePublic(new X509EncodedKeySpec(Arrays.copyOf(clientPubKeyBytes, bytesRead)));

            // Generar el secreto compartido
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(clientPubKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] aesKeyBytes = sha256.digest(sharedSecret);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, 0, 32, "AES");

            System.out.println("Secreto compartido generado.");

            // Recibir el archivo cifrado
            File receivedFile = new File("archivo_recibido.txt");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);

            MessageDigest fileHashDigest = MessageDigest.getInstance("SHA-256");
            try (FileOutputStream fos = new FileOutputStream(receivedFile);
                 DigestOutputStream dos = new DigestOutputStream(fos, fileHashDigest);
                 CipherInputStream cipherInputStream = new CipherInputStream(input, cipher)) {

                byte[] buffer = new byte[1024];
                int len;
                while ((len = cipherInputStream.read(buffer)) != -1) {
                    dos.write(buffer, 0, len);
                }

                System.out.println("Archivo recibido y descifrado: " + receivedFile.getAbsolutePath());
            }

            // Calcular el hash del archivo recibido
            byte[] receivedFileHash = fileHashDigest.digest();
            System.out.println("Hash del archivo recibido: " + bytesToHex(receivedFileHash));

            // Recibir el hash del cliente
            byte[] clientHash = new byte[32];
            try (DataInputStream dis = new DataInputStream(input)) {
                dis.readFully(clientHash); // Leer exactamente 32 bytes
            }
            System.out.println("Hash enviado por el cliente: " + bytesToHex(clientHash));

            // Comparar los hashes
            try (PrintWriter pw = new PrintWriter(output, true)) {
                if (Arrays.equals(receivedFileHash, clientHash)) {
                    System.out.println("El archivo se transfirió correctamente. Los hashes coinciden.");
                    pw.println("Transferencia exitosa: hashes coinciden.");
                } else {
                    System.err.println("Error en la transferencia del archivo. Los hashes no coinciden.");
                    pw.println("Transferencia fallida: hashes no coinciden.");
                }
            }
        } catch (Exception e) {
            System.err.println("Error al comunicarse con el cliente: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                client.close();
            } catch (IOException e) {
                System.err.println("Error al cerrar la conexión: " + e.getMessage());
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
