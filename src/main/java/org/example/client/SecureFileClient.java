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
    private static final String HOST = "localhost";
    private static final int PORT = 12345;
    private static final int BUFFER_SIZE = 8192;

    public static void main(String[] args) {
        handleCommunication();
    }

    private static void handleCommunication() {
        try (Socket socket = new Socket(HOST, PORT);
             Scanner scanner = new Scanner(System.in);
             DataInputStream dis = new DataInputStream(socket.getInputStream());
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            KeyPair keyPair = generateKeyPair();
            PublicKey serverPubKey = exchangePublicKeys(dis, dos, keyPair);

            SecretKeySpec aesKey = generateSharedSecret(keyPair, serverPubKey);

            File fileToSend = promptForFile(scanner);

            sendEncryptedFile(dos, fileToSend, aesKey);

            sendFileHash(dos, fileToSend);

            readServerConfirmation(dis);

        } catch (Exception e) {
            System.err.println("Error in client: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    private static PublicKey exchangePublicKeys(DataInputStream dis, DataOutputStream dos, KeyPair keyPair)
            throws Exception {
        // Receive server's public key
        byte[] serverPubKeyBytes = new byte[dis.readInt()];
        dis.readFully(serverPubKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(serverPubKeyBytes);
        PublicKey serverPubKey = keyFactory.generatePublic(x509Spec);

        // Send client's public key
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        dos.writeInt(publicKeyBytes.length);
        dos.write(publicKeyBytes);
        dos.flush();

        return serverPubKey;
    }

    private static SecretKeySpec generateSharedSecret(KeyPair keyPair, PublicKey serverPubKey)
            throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(serverPubKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();
        System.out.println("Shared secret generated.");
        return new SecretKeySpec(sharedSecret, 0, 32, "AES");
    }

    private static File promptForFile(Scanner scanner) {
        File fileToSend;
        do {
            System.out.println("Enter the name of the file to send: ");
            String fileName = scanner.nextLine();
            fileToSend = new File(fileName);

            if (!fileToSend.exists()) {
                System.out.println("The file does not exist, try again");
            }
        } while (!fileToSend.exists());

        return fileToSend;
    }

    private static void sendEncryptedFile(DataOutputStream dos, File fileToSend, SecretKeySpec aesKey)
            throws Exception {
        // Send filename and file size
        dos.writeUTF(fileToSend.getName());
        dos.writeLong(fileToSend.length());

        // Prepare encryption
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);

        // Encrypt and send file
        byte[] buffer = new byte[BUFFER_SIZE];
        try (FileInputStream fis = new FileInputStream(fileToSend)) {
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] encryptedData = cipher.update(buffer, 0, bytesRead);
                if (encryptedData != null) {
                    dos.writeInt(encryptedData.length);
                    dos.write(encryptedData);
                }
            }

            // Send final encrypted block
            byte[] finalBlock = cipher.doFinal();
            if (finalBlock != null) {
                dos.writeInt(finalBlock.length);
                dos.write(finalBlock);
            }

            dos.writeInt(-1); // End of file signal
            dos.flush();
        }

        System.out.println("File sent and encrypted: " + fileToSend.getAbsolutePath());
    }

    private static void sendFileHash(DataOutputStream dos, File fileToSend) throws Exception {
        byte[] hash = HashUtil.calculateFileHash(fileToSend, "SHA-256");
        System.out.println("File hash: " + HashUtil.bytesToHex(hash));

        dos.writeInt(hash.length);
        dos.write(hash);
        dos.flush();
    }

    private static void readServerConfirmation(DataInputStream dis) throws IOException {
        String confirmation = dis.readUTF();
        System.out.println("Server confirmation: " + confirmation);
    }
}