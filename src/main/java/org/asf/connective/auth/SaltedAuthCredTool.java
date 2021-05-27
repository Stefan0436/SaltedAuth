package org.asf.connective.auth;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import org.asf.connective.standalone.main.CredentialTool.ICredToolTarget;

public class SaltedAuthCredTool implements ICredToolTarget {

	@Override
	public boolean deleteUser(String arg0, String arg1) {
		File cred = SaltedAuth.getFile(new File("credentials"), arg0, arg1);
		if (!cred.exists()) {
			return false;
		} else {
			cred.delete();
			return true;
		}
	}

	@Override
	public User[] lsUsers() {
		ArrayList<User> users = new ArrayList<User>();
		File credFolder = new File("credentials");
		if (credFolder.exists()) {
			for (File f : credFolder.listFiles((file) -> !file.isDirectory() && file.getName().endsWith(".saltcred")
					&& file.getName().startsWith("gr."))) {

				String userdata = f.getName().substring(0, f.getName().lastIndexOf(".saltcred")).substring(3);
				User user = new User();
				user.group = userdata.substring(0, userdata.indexOf("."));
				user.name = userdata.substring(userdata.indexOf(".") + 1);
				users.add(user);
			}
		}
		return users.toArray(t -> new User[t]);
	}

	@Override
	public void setUser(String arg0, String arg1, char[] arg2) throws IOException {
		SaltedAuth.save(arg2, SaltedAuth.getFile(new File("credentials"), arg0, arg1));
	}

	@Override
	public void usageFooter() {
		System.err.println("");
		System.err.println("NOTICE:");
		System.err.println("Running the SaltedAuth CredTool plugin, users are stored in secure saltcred files.");
		System.err.println("");
		System.err.println("");
	}

}
