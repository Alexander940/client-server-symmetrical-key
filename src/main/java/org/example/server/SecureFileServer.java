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
    private static final int PORT = 12345;
    private static final int CLIENT_TIMEOUT = 60000;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("\nServer listening on port " + PORT);

            while (true) {
                Socket client = serverSocket.accept();
                client.setSoTimeout(CLIENT_TIMEOUT);
                System.out.println("Client connected: " + client.getInetAddress().getHostAddress());

                new Thread(() -> handleClient(client)).start();
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }

    private static void handleClient(Socket client) {
        try (client) {
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());

            KeyPair serverKeyPair = generateKeyPair();
            PublicKey clientPubKey = exchangePublicKeys(dis, dos, serverKeyPair);

            SecretKeySpec aesKey = generateSharedSecret(serverKeyPair, clientPubKey);

            FileReceiveResult fileResult = receiveAndDecryptFile(dis, aesKey);

            String confirmationMessage = verifyFileIntegrity(dis, fileResult);

            sendConfirmationToClient(dos, confirmationMessage);

        } catch (Exception e) {
            System.err.println("Client communication error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    private static PublicKey exchangePublicKeys(DataInputStream dis, DataOutputStream dos, KeyPair serverKeyPair)
            throws Exception {
        // Send server's public key
        byte[] publicKeyBytes = serverKeyPair.getPublic().getEncoded();
        dos.writeInt(publicKeyBytes.length);
        dos.write(publicKeyBytes);
        dos.flush();

        // Receive client's public key
        byte[] clientPubKeyBytes = new byte[dis.readInt()];
        dis.readFully(clientPubKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clientPubKeyBytes);
        return keyFactory.generatePublic(x509Spec);
    }

    private static SecretKeySpec generateSharedSecret(KeyPair serverKeyPair, PublicKey clientPubKey)
            throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(serverKeyPair.getPrivate());
        keyAgreement.doPhase(clientPubKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();
        System.out.println("Shared secret generated.");
        return new SecretKeySpec(sharedSecret, 0, 32, "AES");
    }

    private static FileReceiveResult receiveAndDecryptFile(DataInputStream dis, SecretKeySpec aesKey)
            throws Exception {
        // Receive filename and file size
        String fileName = dis.readUTF();
        long fileSize = dis.readLong();

        // Prepare decryption
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);

        // Receive and decrypt file
        File receivedFile = new File("received_" + fileName);
        try (FileOutputStream fos = new FileOutputStream(receivedFile)) {
            while (true) {
                int blockSize = dis.readInt();
                if (blockSize == -1) break; // End of file

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

        System.out.println("File received and decrypted: " + receivedFile.getAbsolutePath());

        return new FileReceiveResult(receivedFile);
    }

    private static String verifyFileIntegrity(DataInputStream dis, FileReceiveResult fileResult)
            throws Exception {
        // Receive hash
        int hashLength = dis.readInt();
        byte[] receivedHash = new byte[hashLength];
        dis.readFully(receivedHash);

        byte[] calculatedHash = HashUtil.calculateFileHash(fileResult.getFile(), "SHA-256");
        System.out.println("Calculated hash: " + HashUtil.bytesToHex(calculatedHash));
        System.out.println("Received hash: " + HashUtil.bytesToHex(receivedHash));

        // Verify integrity
        boolean hashesMatch = Arrays.equals(receivedHash, calculatedHash);
        return hashesMatch ?
                "File received correctly. Hash verified." :
                "Warning! Hashes do not match.";
    }

    private static void sendConfirmationToClient(DataOutputStream dos, String confirmationMessage)
            throws IOException {
        dos.writeUTF(confirmationMessage);
        dos.flush();
    }

    // Helper class to encapsulate file receive result
    private static class FileReceiveResult {
        private final File file;

        public FileReceiveResult(File file) {
            this.file = file;
        }

        public File getFile() {
            return file;
        }
    }
}