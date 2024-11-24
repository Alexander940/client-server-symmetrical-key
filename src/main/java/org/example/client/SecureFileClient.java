package org.example.client;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

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
            PublicKey serverPubKey = KeyFactory.getInstance("DH")
                    .generatePublic(new X509EncodedKeySpec(Arrays.copyOf(serverPubKeyBytes, bytesRead)));

            // Enviar la clave pública del cliente al servidor
            output.write(keyPair.getPublic().getEncoded());
            output.flush();

            // Generar el secreto compartido
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(serverPubKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] aesKeyBytes = sha256.digest(sharedSecret);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, 0, 32, "AES");

            System.out.println("Secreto compartido generado.");

            // Enviar el archivo cifrado
            File fileToSend = new File("archivo.txt");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);

            MessageDigest fileHashDigest = MessageDigest.getInstance("SHA-256");
            try (FileInputStream fis = new FileInputStream(fileToSend);
                 DigestInputStream dis = new DigestInputStream(fis, fileHashDigest);
                 CipherOutputStream cipherOutputStream = new CipherOutputStream(output, cipher)) {

                byte[] buffer = new byte[1024];
                int len;
                while ((len = dis.read(buffer)) != -1) {
                    cipherOutputStream.write(buffer, 0, len);
                }

                cipherOutputStream.flush();
                System.out.println("Archivo enviado y cifrado: " + fileToSend.getAbsolutePath());
            }

            // Calcular el hash del archivo
            byte[] fileHash = fileHashDigest.digest();
            System.out.println("Hash del archivo calculado: " + bytesToHex(fileHash));

            // Enviar el hash al servidor
            try (DataOutputStream dos = new DataOutputStream(output)) {
                dos.write(fileHash); // Enviar el hash de 32 bytes
                dos.flush();
            }
            System.out.println("Hash enviado al servidor.");

            // Recibir confirmación del servidor
            try (BufferedReader serverResponse = new BufferedReader(new InputStreamReader(input))) {
                String confirmation = serverResponse.readLine();
                System.out.println("Respuesta del servidor: " + confirmation);
            }
        } catch (Exception e) {
            System.err.println("Error en el cliente: " + e.getMessage());
            e.printStackTrace();
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
