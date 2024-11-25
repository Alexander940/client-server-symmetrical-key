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
            DataOutputStream dos = new DataOutputStream(output);
            DataInputStream dis = new DataInputStream(input);

            // Generar claves y establecer el secreto compartido
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            byte[] serverPubKeyBytes = new byte[2048];
            int bytesRead = input.read(serverPubKeyBytes);
            byte[] trimmedBytes = new byte[bytesRead];
            System.arraycopy(serverPubKeyBytes, 0, trimmedBytes, 0, bytesRead);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(trimmedBytes);
            PublicKey serverPubKey = keyFactory.generatePublic(x509Spec);

            output.write(keyPair.getPublic().getEncoded());
            output.flush();

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(serverPubKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");
            System.out.println("Secreto compartido generado.");

            // Enviar archivo cifrado
            File fileToSend = new File("archivo.txt");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);

            try (CipherOutputStream cipherOutputStream = new CipherOutputStream(output, cipher);
                 FileInputStream fis = new FileInputStream(fileToSend)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    cipherOutputStream.write(buffer, 0, len);
                }
                cipherOutputStream.flush();
            }
            System.out.println("Archivo enviado y cifrado: " + fileToSend.getAbsolutePath());

            // Calcular y enviar el hash
            byte[] hash = calculateFileHash(fileToSend, "SHA-256");
            System.out.println("Llego hasta aqui");
            dos.writeInt(hash.length); // Primero envía la longitud del hash
            System.out.println("Llego hasta aqui 2");
            dos.write(hash);           // Luego envía los bytes del hash
            dos.flush();

            // Leer confirmación del servidor
            String confirmation = dis.readUTF();
            System.out.println("Confirmación del servidor: " + confirmation);
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
