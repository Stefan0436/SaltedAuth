package org.asf.connective.auth;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.asf.cyan.api.common.CYAN_COMPONENT;
import org.asf.cyan.api.common.CyanComponent;
import org.asf.rats.IAuthenticationProvider;
import org.asf.rats.Memory;

@CYAN_COMPONENT
public class SaltedAuth extends CyanComponent {

	public static class CredContainer {
		public byte[] hash;
		public byte[] salt;

		public CredContainer read(File input) throws IOException {
			FileInputStream strm = new FileInputStream(input);
			int length = ByteBuffer.wrap(strm.readNBytes(4)).getInt();
			salt = new byte[length];
			for (int i = 0; i < length; i++) {
				salt[i] = (byte) strm.read();
			}
			length = ByteBuffer.wrap(strm.readNBytes(4)).getInt();
			hash = new byte[length];
			for (int i = 0; i < length; i++) {
				hash[i] = (byte) strm.read();
			}
			strm.close();
			return this;
		}

		public CredContainer write(File output) throws IOException {
			if (!output.getParentFile().exists())
				output.getParentFile().mkdirs();
			FileOutputStream strm = new FileOutputStream(output);
			strm.write(ByteBuffer.allocate(4).putInt(salt.length).array());
			strm.write(salt);
			strm.write(ByteBuffer.allocate(4).putInt(hash.length).array());
			strm.write(hash);
			strm.close();
			return this;
		}

		public CredContainer assign(byte[] salt, byte[] hash) {
			this.salt = salt;
			this.hash = hash;
			return this;
		}

		public void destroy() {
			for (int i = 0; i < salt.length; i++) {
				salt[i] = 0;
			}
			for (int i = 0; i < hash.length; i++) {
				hash[i] = 0;
			}
		}
	}

	protected static void initComponent() {
		info("Running the SaltedAuth module, installing authentication provider...");

		SaltedAuthProvider provider = new SaltedAuthProvider(
				Memory.getInstance().get("connective.standard.authprovider").getValue(IAuthenticationProvider.class));
		Memory.getInstance().get("connective.standard.authprovider").assign(provider);
	}

	private static SecureRandom rnd = new SecureRandom();

	private static byte[] salt() {
		byte[] salt = new byte[32];
		rnd.nextBytes(salt);
		return salt;
	}

	public static void save(char[] password, File userFile) throws IOException {
		byte[] salt = salt();
		byte[] hash = getHash(salt, password);
		new CredContainer().assign(salt, hash).write(userFile);
	}

	public static byte[] getHash(byte[] salt, char[] password) {
		KeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			return factory.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			return null;
		}
	}

	public static File getFile(File authDir, String group, String username) {
		return new File(authDir, "gr." + group + "." + username + ".saltcred");
	}

	public static File getCredToolFile(File authDir, String group, String username) {
		return new File(authDir, "gr." + group + "." + username + ".cred");
	}

}
