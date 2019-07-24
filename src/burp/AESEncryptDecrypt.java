package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AESEncryptDecrypt {

    private static byte[] key;


    public AESEncryptDecrypt() {
        setKey(new String(genRandomKey(), Charset.forName("UTF-8")));
    }

    public AESEncryptDecrypt(String key) {
        setKey(key);
    }

    public String encrypt(String text) throws Exception {
        SecureRandom rand = new SecureRandom();
        SecretKeySpec key_spec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        byte[] encoded_payload = text.getBytes(UTF_8);
        int block_size = cipher.getBlockSize();
        byte[] buffer = new byte[block_size];
        rand.nextBytes(buffer);
        IvParameterSpec iv = new IvParameterSpec(buffer);
        buffer = Arrays.copyOf(buffer, block_size + encoded_payload.length);
        cipher.init(Cipher.ENCRYPT_MODE, key_spec, iv);
        cipher.doFinal(encoded_payload, 0, encoded_payload.length, buffer, block_size);
        return Base64.getEncoder().encodeToString(buffer);
    }

    public String decrypt(String payload) {
        try {
            byte[] ciphertext = Base64.getDecoder().decode(payload);
            SecretKeySpec key_spec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            int block_size = cipher.getBlockSize();
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOf(ciphertext, block_size));
            byte[] decryption_data = Arrays.copyOfRange(ciphertext, block_size, ciphertext.length);
            cipher.init(Cipher.DECRYPT_MODE, key_spec, iv);
            return new String(cipher.doFinal(decryption_data));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private byte[] genRandomKey() {
        byte[] array = new byte[32];
        new Random().nextBytes(array);
        return array;

    }

    public void setKey(String myKey) {
        key = myKey.getBytes(UTF_8);
    }
}
