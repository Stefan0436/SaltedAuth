package org.asf.connective.auth;

import java.io.File;
import java.io.IOException;

import org.asf.rats.IAuthenticationProvider;

public class SaltedAuthProvider implements IAuthenticationProvider {

	private IAuthenticationProvider delegate;
	private static SaltedAuthProvider instance;
	
	public static SaltedAuthProvider getInstance() {
		return instance;
	}

	private String serverDir = System.getProperty("rats.config.dir") == null ? "."
			: System.getProperty("rats.config.dir");
	private File authDir;

	public SaltedAuthProvider(IAuthenticationProvider delegate) {
		this.delegate = delegate;
		authDir = new File(serverDir, "credentials");
		instance = this;
	}

	@Override
	public boolean authenticate(String group, String username, char[] password) throws IOException {
		if (!username.matches("^[A-Za-z0-9\\-@. ']+$") || !group.matches("^[A-Za-z0-9]+$"))
			return false;

		File userFile = SaltedAuth.getFile(authDir, group, username);
		if (!userFile.exists()) {
			if (delegate.authenticate(group, username, password)) {
				SaltedAuth.save(password, userFile);

				if (new File(authDir, "gr." + group + "." + username + ".cred").exists()) {

					// Delete the old file
					new File(authDir, "gr." + group + "." + username + ".cred").delete();

				}

				return true;
			}
			return false;
		} else {
			SaltedAuth.CredContainer container = new SaltedAuth.CredContainer().read(userFile);
			byte[] hash = SaltedAuth.getHash(container.salt, password);
			if (hash.length != container.hash.length) {
				container.destroy();
				return false;
			}
			for (int i = 0; i < hash.length; i++) {
				if (hash[i] != container.hash[i]) {
					container.destroy();
					return false;
				}
			}
			container.destroy();
			return true;
		}
	}

}
