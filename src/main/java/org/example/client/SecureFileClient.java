package org.example.client;

import org.example.util.HashUtil;

import javax.crypto.Cipher;
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
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

            // Generar claves y establecer el secreto compartido
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Intercambio de claves públicas
            byte[] serverPubKeyBytes = new byte[dis.readInt()];
            dis.readFully(serverPubKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(serverPubKeyBytes);
            PublicKey serverPubKey = keyFactory.generatePublic(x509Spec);

            // Enviar clave pública del cliente
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            dos.writeInt(publicKeyBytes.length);
            dos.write(publicKeyBytes);
            dos.flush();

            // Generar secreto compartido
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(serverPubKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");
            System.out.println("Secreto compartido generado.");

            // Solicitar archivo
            String fileName = "";
            boolean exists = true;
            do {
                if(!exists) {
                    System.out.println("El archivo no existe, intenta de nuevo");
                }
                System.out.println("Ingresa el nombre del archivo a enviar: ");
                fileName = scanner.nextLine();
                exists = new File(fileName).exists();
            } while (!exists);

            File fileToSend = new File(fileName);

            // Enviar nombre del archivo
            dos.writeUTF(fileToSend.getName());

            // Enviar tamaño del archivo
            dos.writeLong(fileToSend.length());

            // Preparar cifrado
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);

            // Enviar archivo cifrado
            byte[] buffer = new byte[8192];
            int bytesRead;
            try (FileInputStream fis = new FileInputStream(fileToSend)) {
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] encryptedData = cipher.update(buffer, 0, bytesRead);
                    if (encryptedData != null) {
                        dos.writeInt(encryptedData.length);
                        dos.write(encryptedData);
                    }
                }
                byte[] finalBlock = cipher.doFinal();
                if (finalBlock != null) {
                    dos.writeInt(finalBlock.length);
                    dos.write(finalBlock);
                }
                dos.writeInt(-1); // Señal de fin de archivo
                dos.flush();
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
            e.printStackTrace();
        }
    }
}