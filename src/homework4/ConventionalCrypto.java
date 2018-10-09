package homework4;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

// encrypt and decrypt using the DES private key algorithm
public class ConventionalCrypto {

	public static Key genKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
		keyGen.init(112);
		return keyGen.generateKey();
	}

	public static byte[] encrypt(String plaintext, Cipher cipher, Key key, IvParameterSpec ivspec)
			throws IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
		return cipher.doFinal(plaintext.getBytes("UTF8"));
	}

	public static String decrypt(byte[] ciphertext, Cipher cipher, Key key, IvParameterSpec ivspec)
			throws InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
		return new String(cipher.doFinal(ciphertext), "UTF8");
	}

	public static void main(String[] args) throws Exception {

		// Check args and get plaintext
		if (args.length != 1) {
			System.err.println("Usage: java ConventionalCrypto text");
			System.exit(1);
		}
		String plaintext = args[0];
		IvParameterSpec ivspec = new IvParameterSpec(new SecureRandom().generateSeed(8));

		// get a DES private key
		System.out.println("\nStart generating 3DES key");
		Key key = genKey();
		System.out.print("Finish generating 3DES key: ");
		System.out.println(Base64.encodeBase64String(key.getEncoded()));

		// Create a DES cipher object
		Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");

		// Encrypt using the key and the plaintext
		System.out.println("\nStart encryption");
		byte[] ciphertext = encrypt(plaintext, cipher, key, ivspec);
		System.out.print("Finish encryption: ");
		System.out.println(new String(ciphertext, "UTF8"));

		// Decrypt the ciphertext using a key input from the user
		System.out.println("\nStart decryption");
		System.out.print("Enter the key to decode the ciphertext: ");
		Scanner scan = new Scanner(System.in);
		Key newKey = new SecretKeySpec(Base64.decodeBase64(scan.nextLine().getBytes()),"DESede");
		scan.close();
		
		String newPlaintext = decrypt(ciphertext, cipher, newKey, ivspec);
		System.out.print("Finish decryption: ");
		System.out.println(newPlaintext);
	}
}
