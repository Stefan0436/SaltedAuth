package org.asf.connective.auth;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;

import org.asf.connective.usermanager.api.AuthResult;
import org.asf.connective.usermanager.api.IAuthenticationBackend;
import org.asf.connective.usermanager.backends.CredToolBackend;
import org.asf.cyan.api.common.CyanComponent;
import org.asf.rats.HttpRequest;
import org.asf.rats.HttpResponse;
import org.asf.rats.IAuthenticationProvider;
import org.asf.rats.Memory;

public class SaltedAuthBackend extends CyanComponent implements IAuthenticationBackend {

	private String serverDir = System.getProperty("rats.config.dir") == null ? "."
			: System.getProperty("rats.config.dir");
	private File authDir = new File(serverDir, "credentials");

	private CredToolBackend delegate = new CredToolBackend();

	@Override
	public String name() {
		return "salted";
	}

	@Override
	public boolean available() {
		try {
			Class.forName("org.asf.connective.auth.SaltedAuthProvider");
			Class.forName("org.asf.connective.auth.SaltedAuth");

			IAuthenticationProvider prov = Memory.getInstance().get("connective.standard.authprovider")
					.getValue(IAuthenticationProvider.class);
			if (prov == null || !(prov instanceof SaltedAuthProvider))
				return false;

			return true;
		} catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean userExists(String group, String username) throws IOException {
		File userFile = SaltedAuth.getFile(authDir, group, username);
		if (!userFile.exists() && SaltedAuth.getCredToolFile(authDir, group, username).exists())
			return true;
		return userFile.exists();
	}

	@Override
	public void updateUser(String group, String username, char[] password) throws IOException {
		SaltedAuth.save(password, SaltedAuth.getFile(authDir, group, username));
	}

	@Override
	public boolean validateUsername(String username) {
		return username.matches("^[A-Za-z0-9\\-@. ']+$");
	}

	@Override
	public boolean validateGroupname(String group) {
		return group.matches("^[A-Za-z0-9]+$");
	}

	@Override
	public AuthResult authenticate(String group, HttpRequest request, HttpResponse response) {
		return delegate.authenticate(group, request, response);
	}

	@Override
	public void deleteUser(String group, String username) throws IOException {
		File userFile = SaltedAuth.getFile(authDir, group, username);
		if (userFile.exists())
			userFile.delete();
	}

	@Override
	public String[] getUsers(String group) throws IOException {
		ArrayList<String> users = new ArrayList<String>();
		for (File user : authDir.listFiles(t -> {
			return !t.isDirectory() && t.getName().startsWith("gr." + group + ".") && t.getName().endsWith(".saltcred");
		})) {
			String username = user.getName().substring(("gr." + group + ".").length());
			username = username.substring(0, username.lastIndexOf(".saltcred"));
			users.add(username);
		}
		return users.toArray(t -> new String[t]);
	}

	@Override
	public void setNewUserName(String group, String oldName, String newName) throws IOException {
		File oldFile = SaltedAuth.getFile(authDir, group, oldName);
		File newFile = SaltedAuth.getFile(authDir, group, newName);
		Files.move(oldFile.toPath(), newFile.toPath());
	}

}
