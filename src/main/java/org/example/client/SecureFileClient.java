package org.example.client;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class SecureFileClient {
    public static void main(String[] args) {
        String host = "localhost";
        int port = 12345;

        try (Socket socket = new Socket(host, port)) {
            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();

            // Generar las claves Diffie-Hellman
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Recibir la clave pública del servidor
            byte[] serverPubKeyBytes = new byte[2048];
            int bytesRead = input.read(serverPubKeyBytes);
            byte[] trimmedBytes = new byte[bytesRead];
            System.arraycopy(serverPubKeyBytes, 0, trimmedBytes, 0, bytesRead);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(trimmedBytes);
            PublicKey serverPubKey = keyFactory.generatePublic(x509Spec);

            // Enviar la clave pública del cliente al servidor
            output.write(keyPair.getPublic().getEncoded());
            output.flush();

            // Generar el secreto compartido
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(serverPubKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

            System.out.println("Secreto compartido generado.");

            // Enviar el archivo cifrado
            File fileToSend = new File("archivo.txt");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            try (FileInputStream fis = new FileInputStream(fileToSend);
                 CipherOutputStream cipherOutputStream = new CipherOutputStream(output, cipher)) {

                byte[] buffer = new byte[1024];
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    cipherOutputStream.write(buffer, 0, len);
                }

                cipherOutputStream.flush();
                fis.close();
                System.out.println("Archivo enviado y cifrado: " + fileToSend.getAbsolutePath());
            }

            byte[] hash = new byte[0];

            try {
                hash = calculateFileHash(fileToSend, "SHA-256");
                System.out.println("Hash del archivo: " + bytesToHex(hash));
            } catch (Exception e) {
                System.err.println("Error al calcular el hash del archivo: " + e.getMessage());
                e.printStackTrace();
            }

            try (DataOutputStream dos = new DataOutputStream(output)) {
                String hashHex = bytesToHex(hash); // Convierte el hash a formato hexadecimal
                dos.writeUTF(hashHex); // Escribe el hash como una cadena de texto
                dos.flush();
            }
            System.out.println("Hash enviado al servidor.");

            // Leer confirmación del servidor
            try (DataInputStream dis = new DataInputStream(input)) {
                String confirmation = dis.readUTF();
                System.out.println("Confirmación del servidor: " + confirmation);
                dis.close();
            }

        } catch (Exception e) {
            System.err.println("Error en el cliente: " + e.getMessage());
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
