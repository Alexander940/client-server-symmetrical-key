package org.example.client;

import org.example.util.HashUtil;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class SecureFileClient {
    public static void main(String[] args) {
        String host = "localhost";
        int port = 12345;

        while (true) {
            handleCommunication(host, port);
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

    }

    public static void handleCommunication(String host, int port) {
        try (Socket socket = new Socket(host, port)) {
            Scanner scanner = new Scanner(System.in);
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
            String fileName = "";
            boolean exists = true;
            do{
                if(!exists){
                    System.out.println("El archivo no existe, intenta de nuevo");
                }
                System.out.println("Ingresa el nombre del archivo a enviar: ");
                fileName = scanner.nextLine();
                exists = new File(fileName).exists();
            } while (!exists);

            File fileToSend = new File(fileName);
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
            byte[] hash = HashUtil.calculateFileHash(fileToSend, "SHA-256");
            System.out.println("Hash del archivo: " + HashUtil.bytesToHex(hash));

            dos.writeInt(hash.length);
            dos.write(hash);
            dos.flush();

            // Leer confirmación del servidor
            String confirmation = dis.readUTF();
            System.out.println("Confirmación del servidor: " + confirmation);
        } catch (Exception e) {
            System.err.println("Error en el cliente: " + e.getMessage());
        }
    }
}
