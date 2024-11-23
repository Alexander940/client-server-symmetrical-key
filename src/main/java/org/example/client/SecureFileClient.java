package org.example.client;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

public class SecureFileClient {
    public static void main(String[] args) throws Exception {
        String serverAddress = "localhost";
        int port = 12345;

        while (true) {
            Socket socket = new Socket(serverAddress, port);
            System.out.println("Conectado al servidor.");

            try {
                // Establecer Diffie-Hellman para negociar la clave
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
                keyPairGenerator.initialize(2048);
                KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();

                // Recibir la clave pública del servidor
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                PublicKey serverPublicKey = (PublicKey) in.readObject();

                // Enviar la clave pública al servidor
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(clientKeyPair.getPublic());
                out.flush();

                // Generar la clave secreta compartida
                KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                keyAgreement.init(clientKeyPair.getPrivate());
                keyAgreement.doPhase(serverPublicKey, true);
                byte[] sharedSecret = keyAgreement.generateSecret();

                // Derivar una clave AES de 256 bits de la clave compartida
                byte[] aesKeyBytes = Arrays.copyOf(sharedSecret, 32);
                SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
                System.out.println("Clave AES derivada por el cliente: " + Arrays.toString(aesKeyBytes));

                // Solicitar al usuario la ruta del archivo
                Scanner scanner = new Scanner(System.in);
                System.out.println("Ingrese la ruta completa del archivo a transferir:");
                String filePath = scanner.nextLine();
                File file = new File(filePath);

                // Validar si el archivo existe
                if (!file.exists()) {
                    System.out.println("El archivo no existe en la ruta proporcionada: " + file.getAbsolutePath());
                    socket.close();
                    continue; // Volver al inicio para solicitar otra ruta
                }

                // Configurar cifrado AES
                Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

                // Cifrar y enviar el archivo
                FileInputStream fis = new FileInputStream(file);
                CipherOutputStream cos = new CipherOutputStream(socket.getOutputStream(), aesCipher);
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
                fis.close();
                cos.flush();
                socket.shutdownOutput();
                System.out.println("Archivo enviado.");

                // Calcular hash SHA-256 del archivo enviado
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                fis = new FileInputStream(file);
                while ((bytesRead = fis.read(buffer)) != -1) {
                    sha256.update(buffer, 0, bytesRead);
                }
                fis.close();
                byte[] fileHash = sha256.digest();
                System.out.println("Hash calculado por el cliente: " + Arrays.toString(fileHash));

                // Recibir hash del servidor y verificar integridad
                byte[] serverHash = (byte[]) in.readObject();
                System.out.println("Hash recibido del servidor: " + Arrays.toString(serverHash));
                if (MessageDigest.isEqual(fileHash, serverHash)) {
                    System.out.println("El archivo se transfirió correctamente.");
                } else {
                    System.out.println("Error en la transferencia del archivo: Hash no coincide.");
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                socket.close();
                System.out.println("Conexión cerrada. Puede ingresar otra ruta.");
            }
        }
    }
}
