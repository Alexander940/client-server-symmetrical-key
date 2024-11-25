package org.example.server;

import org.example.util.HashUtil;

import javax.crypto.Cipher;
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
                client.setSoTimeout(60000);
                System.out.println("Cliente conectado: " + client.getInetAddress().getHostAddress());

                new Thread(() -> handleClient(client)).start();
            }
        } catch (IOException e) {
            System.err.println("Error en el servidor: " + e.getMessage());
        }
    }

    private static void handleClient(Socket client) {
        try {
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());

            // Generar claves y establecer el secreto compartido
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Enviar clave pública del servidor
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            dos.writeInt(publicKeyBytes.length);
            dos.write(publicKeyBytes);
            dos.flush();

            // Recibir clave pública del cliente
            byte[] clientPubKeyBytes = new byte[dis.readInt()];
            dis.readFully(clientPubKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clientPubKeyBytes);
            PublicKey clientPubKey = keyFactory.generatePublic(x509Spec);

            // Generar secreto compartido
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(clientPubKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");
            System.out.println("Secreto compartido generado.");

            // Recibir nombre y tamaño del archivo
            String fileName = dis.readUTF();
            long fileSize = dis.readLong();

            // Preparar descifrado
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);

            // Recibir y descifrar archivo
            File receivedFile = new File("received_" + fileName);
            try (FileOutputStream fos = new FileOutputStream(receivedFile)) {
                while (true) {
                    int blockSize = dis.readInt();
                    if (blockSize == -1) break; // Fin del archivo

                    byte[] encryptedBlock = new byte[blockSize];
                    dis.readFully(encryptedBlock);
                    byte[] decryptedBlock = cipher.update(encryptedBlock);
                    if (decryptedBlock != null) {
                        fos.write(decryptedBlock);
                    }
                }
                byte[] finalBlock = cipher.doFinal();
                if (finalBlock != null) {
                    fos.write(finalBlock);
                }
            }

            System.out.println("Archivo recibido y descifrado: " + receivedFile.getAbsolutePath());

            // Recibir y verificar hash
            int hashLength = dis.readInt();
            byte[] receivedHash = new byte[hashLength];
            dis.readFully(receivedHash);

            byte[] calculatedHash = HashUtil.calculateFileHash(receivedFile, "SHA-256");
            System.out.println("Hash calculado: " + HashUtil.bytesToHex(calculatedHash));
            System.out.println("Hash recibido: " + HashUtil.bytesToHex(receivedHash));

            // Verificar integridad
            boolean hashesMatch = Arrays.equals(receivedHash, calculatedHash);
            String confirmationMessage = hashesMatch ?
                    "Archivo recibido correctamente. Hash verificado." :
                    "¡Advertencia! Los hashes no coinciden.";

            // Enviar confirmación al cliente
            dos.writeUTF(confirmationMessage);
            dos.flush();

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
}