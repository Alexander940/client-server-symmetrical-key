package org.example.server;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLOutput;

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
                OutputStream output = client.getOutputStream();
                DataInputStream dis = new DataInputStream(input);
                DataOutputStream dos = new DataOutputStream(output)
        ) {
            // Generar claves y establecer el secreto compartido
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            output.write(keyPair.getPublic().getEncoded());
            output.flush();

            byte[] clientPubKeyBytes = new byte[2048];
            int bytesRead = input.read(clientPubKeyBytes);
            byte[] trimmedBytes = new byte[bytesRead];
            System.arraycopy(clientPubKeyBytes, 0, trimmedBytes, 0, bytesRead);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(trimmedBytes);
            PublicKey clientPubKey = keyFactory.generatePublic(x509Spec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(clientPubKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");
            System.out.println("Secreto compartido generado.");

            // Recibir el archivo cifrado
            File receivedFile = new File("archivo_recibido.txt");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);

            try (CipherInputStream cipherInputStream = new CipherInputStream(input, cipher);
                 FileOutputStream fos = new FileOutputStream(receivedFile)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = cipherInputStream.read(buffer)) != -1) {
                    fos.write(buffer, 0, len);
                }
            }
            System.out.println("Archivo recibido y descifrado: " + receivedFile.getAbsolutePath());

            int hashLength = dis.readInt(); // Leer la longitud del hash
            byte[] hash = new byte[hashLength];
            dis.readFully(hash);

            // Calcular el hash del archivo recibido
            byte[] fileHash = calculateFileHash(receivedFile, "SHA-256");
            System.out.println("Hash del archivo: " + bytesToHex(fileHash));

            // Enviar confirmación al cliente
            dos.writeUTF("Archivo y hash recibidos correctamente.");
            dos.flush();
        } catch (Exception e) {
            System.err.println("Error al comunicarse con el cliente: " + e.getMessage());
        } finally {
            /*try {
                client.close();
            } catch (IOException e) {
                System.err.println("Error al cerrar la conexión: " + e.getMessage());
            }*/
        }
    }

    public static byte[] calculateFileHash(File file, String algorithm) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                messageDigest.update(buffer, 0, bytesRead);
            }
        }
        return messageDigest.digest();
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
