import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class PasswordGenerator {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 128; // 128-bit key
    private static final String CHARSET = "UTF-8";

    public static void main(String[] args) throws Exception {
        // Generate a secret key for encryption
        Key secretKey = generateSecretKey();

        // Create a password generator
        PasswordGenerator generator = new PasswordGenerator();

        // Generate a password for a specific account (e.g., email, social media, etc.)
        String accountName = "example@email.com";
        String password = generator.generatePassword(12); // 12-character password
        System.out.println("Generated password for " + accountName + ": " + password);

        // Encrypt the password using the secret key
        String encryptedPassword = encrypt(password, secretKey);
        System.out.println("Encrypted password: " + encryptedPassword);

        // Store the encrypted password securely (e.g., in a database or file)

        // Later, when you need to retrieve the password...
        String decryptedPassword = decrypt(encryptedPassword, secretKey);
        System.out.println("Decrypted password: " + decryptedPassword);
    }

    private static Key generateSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        return keyGen.generateKey();
    }

    private String generatePassword(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int randomInt = random.nextInt(94) + 33; // ASCII range: 33 to 126
            password.append((char) randomInt);
        }
        return password.toString();
    }

    public static String encrypt(String password, Key secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedPassword, Key secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedBytes, CHARSET);
    }
}