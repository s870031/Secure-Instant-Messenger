package chat_client;

import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import java.util.Base64;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class client_frame extends javax.swing.JFrame 
{
	String username,password,address = "localhost";
	ArrayList<String> users = new ArrayList();
	int port = 2222;
	Boolean isConnected = false;

	Socket sock;
	//BufferedReader reader;
	ObjectInputStream ois;
	//PrintWriter writer;
	ObjectOutputStream oos;
        
        // DES key
        String xform = "DES/ECB/PKCS5Padding"; // Encrypt type
        //String stringKey = "H4oHCAioTMI=";
	//byte[] decodedKey = Base64.getDecoder().decode(stringKey);
	//SecretKey myDesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
        SecretKey myDesKey;
	
        

	//--------------------------//

	public void ListenThread() 
	{
		Thread IncomingReader = new Thread(new IncomingReader());
		IncomingReader.start();
	}

	//--------------------------//

	public void userAdd(String data) 
	{
		users.add(data);
	}

	//--------------------------//

	public void userRemove(String data) 
	{
		ta_chat.append(data + " is now offline.\n");
	}

	//--------------------------//

	public void writeUsers() 
	{
		String[] tempList = new String[(users.size())];
		users.toArray(tempList);
		for (String token:tempList) 
		{
			//users.append(token + "\n");
		}
	}

	//--------------------------//

	public void sendDisconnect() 
	{
		String bye = (username + ": :Disconnect");
		try
		{
			//writer.println(bye); 
			oos.writeObject(bye);
			//writer.flush(); 
			oos.flush();
		} catch (Exception e) 
		{
			ta_chat.append("Could not send Disconnect message.\n");
		}
	}

	//--------------------------//

	public void Disconnect() 
	{
		try 
		{
			ta_chat.append("Disconnected.\n");
			sock.close();
		} catch(Exception ex) {
			ta_chat.append("Failed to disconnect. \n");
		}
		isConnected = false;
		tf_username.setEditable(true);
		tf_password.setEditable(true);

	}

	public client_frame() 
	{
		initComponents();
	}

	//--------------------------//
	//hashing of message
	static String sha1(String input) throws NoSuchAlgorithmException
	{
		MessageDigest mDigest = MessageDigest.getInstance("SHA1");
		byte[] result = mDigest.digest(input.getBytes());
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < result.length; i++) {
			sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
		}
		return sb.toString();
	}
        static byte[] encrypt(byte[] inpBytes, SecretKey key,
			String xform) throws Exception{
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
        static byte[] decrypt(byte[] inpBytes, SecretKey key,
			String xform) throws Exception{
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}

	public class IncomingReader implements Runnable
	{
		@Override
		public void run() 
		{
			String[] data;
			String stream, done = "Done", connect = "Connect",
                                disconnect = "Disconnect", chat = "Chat", key = "Key";
                
			Object obj = null;

			try 
			{
				//while ((stream = reader.readLine()) != null) 
				while ((obj = ois.readObject()) != null)
				{
                                    if (obj instanceof String) {
                                            stream = (String)obj;
                                            data = stream.split(":");

                                            if (data[2].equals(chat)) 
                                            {
                                                    ta_chat.append("\n" + data[0] + ": " + data[1] + "\n");
                                                    //ta_chat.append(sha1(data[1] + "\n" +"\n"));
                                                    // tellEveryone(sha1(message));
                                                    ta_chat.setCaretPosition(ta_chat.getDocument().getLength());
                                            } 
                                            else if (data[2].equals(connect))
                                            {
                                                    ta_chat.removeAll();
                                                    userAdd(data[0]);
                                            } 
                                            else if (data[2].equals(disconnect)) 
                                            {
                                                    userRemove(data[0]);
                                            } 
                                            else if (data[2].equals(done)) 
                                            {
                                                    //users.setText("");
                                                    writeUsers();
                                                    users.clear();
                                            }
                                            else if (data[2].equals(key)){
                                                String stringKey = data[1];
                                                byte[] decodedKey = Base64.getDecoder().decode(stringKey);
                                                myDesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
                                                ta_chat.append("Get session key: " + data[1] + "\n");
                                            }
                                    }
                                    // Get encrypt chat message
                                    else if (obj instanceof byte[]){
                                        byte[] encBytes = (byte[])obj;
                                        // Decrypt message
                                        byte[] decBytes = decrypt(encBytes,myDesKey,xform);
                                        String msg = new String(decBytes);
                                        ta_chat.append(msg + "\n");
                                        ta_chat.append(sha1(msg)+"\n\n");
                                    }
				}
			}catch(Exception ex) { }
		}
	}

	//--------------------------//

	@SuppressWarnings("unchecked")
	// <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
	private void initComponents() {

		lb_address = new javax.swing.JLabel();
		tf_address = new javax.swing.JTextField();
		lb_port = new javax.swing.JLabel();
		tf_port = new javax.swing.JTextField();
		lb_username = new javax.swing.JLabel();
		tf_username = new javax.swing.JTextField();
		lb_password = new javax.swing.JLabel();
		tf_password = new javax.swing.JTextField();
		b_connect = new javax.swing.JButton();
		b_disconnect = new javax.swing.JButton();
		jScrollPane1 = new javax.swing.JScrollPane();
		ta_chat = new javax.swing.JTextArea();
		tf_chat = new javax.swing.JTextField();
		b_send = new javax.swing.JButton();
		BuddyList = new javax.swing.JButton();

		setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
		setTitle("Chat - Client's frame");
		setName("client"); // NOI18N
		setResizable(false);

		lb_address.setText("Address : ");

		tf_address.setText("localhost");
		tf_address.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				tf_addressActionPerformed(evt);
			}
		});

		lb_port.setText("Port :");

		tf_port.setText("2222");
		tf_port.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				tf_portActionPerformed(evt);
			}
		});

		lb_username.setText("Username :");

		tf_username.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				tf_usernameActionPerformed(evt);
			}
		});

		lb_password.setText("Password : ");

		tf_password.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				tf_passwordActionPerformed(evt);
			}
		});

		b_connect.setText("Connect");
		b_connect.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				b_connectActionPerformed(evt);
			}
		});

		b_disconnect.setText("Disconnect");
		b_disconnect.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				b_disconnectActionPerformed(evt);
			}
		});

		ta_chat.setColumns(20);
		ta_chat.setRows(5);
		jScrollPane1.setViewportView(ta_chat);

		b_send.setText("SEND");
		b_send.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				b_sendActionPerformed(evt);
			}
		});

		BuddyList.setText("Buddy List");
		BuddyList.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				BuddyListActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(
				layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
					.addContainerGap()
					.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(layout.createSequentialGroup()
							.addComponent(tf_chat, javax.swing.GroupLayout.PREFERRED_SIZE, 352, javax.swing.GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
							.addComponent(b_send, javax.swing.GroupLayout.DEFAULT_SIZE, 166, Short.MAX_VALUE))
						.addComponent(jScrollPane1)
						.addGroup(layout.createSequentialGroup()
							.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
								.addComponent(lb_username, javax.swing.GroupLayout.PREFERRED_SIZE, 62, Short.MAX_VALUE)
								.addComponent(lb_address, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
							.addGap(18, 18, 18)
							.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(tf_address, javax.swing.GroupLayout.DEFAULT_SIZE, 89, Short.MAX_VALUE)
								.addComponent(tf_username))
							.addGap(18, 18, 18)
							.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(lb_password, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(lb_port, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
							.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
							.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(tf_password)
								.addComponent(tf_port, javax.swing.GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE))
							.addGap(35, 35, 35)
							.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(b_disconnect, javax.swing.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE)
								.addComponent(b_connect, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
							.addGap(0, 0, Short.MAX_VALUE)))
							.addContainerGap())
							.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
									.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
									.addComponent(BuddyList, javax.swing.GroupLayout.PREFERRED_SIZE, 165, javax.swing.GroupLayout.PREFERRED_SIZE)
									.addGap(167, 167, 167))
							);
		layout.setVerticalGroup(
				layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
					.addContainerGap()
					.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
						.addComponent(lb_address)
						.addComponent(tf_address, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addComponent(lb_port)
						.addComponent(tf_port, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addComponent(b_connect))
					.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
					.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
						.addComponent(tf_username)
						.addComponent(tf_password)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
							.addComponent(lb_username)
							.addComponent(lb_password)
							.addComponent(b_disconnect)))
					.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
					.addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 310, javax.swing.GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
					.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addComponent(tf_chat)
						.addComponent(b_send, javax.swing.GroupLayout.DEFAULT_SIZE, 34, Short.MAX_VALUE))
					.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
					.addComponent(BuddyList)
					.addGap(7, 7, 7))
					);

		pack();
	}// </editor-fold>//GEN-END:initComponents

	private void tf_addressActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_addressActionPerformed

	}//GEN-LAST:event_tf_addressActionPerformed

	private void tf_portActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_portActionPerformed

	}//GEN-LAST:event_tf_portActionPerformed

	private void tf_usernameActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_usernameActionPerformed

	}//GEN-LAST:event_tf_usernameActionPerformed

	private void b_connectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_connectActionPerformed
		if (isConnected == false) 
		{
			username = tf_username.getText(); //entering the User ID for client
			tf_username.setEditable(false); //make it un editable for that session
			password=tf_password.getText(); //entering the Password for the Client
			tf_password.setEditable(false);
			//   password.setEditable(false);
			//assigning the user Id and password for Signing in 
			if(username.contentEquals("bhanu") && password.contentEquals("arora"))
			{
				try 
				{
					sock = new Socket(address, port);
					//InputStreamReader streamreader = new InputStreamReader(sock.getInputStream());
					//reader = new BufferedReader(streamreader);
					ois = new ObjectInputStream(sock.getInputStream());
					//writer = new PrintWriter(sock.getOutputStream());
					oos = new ObjectOutputStream(sock.getOutputStream());
					//writer.println(username + ":has connected.:Connect");
					oos.writeObject(username + ":has connected.:Connect");
					//writer.flush(); 
					oos.flush();
					isConnected = true; 
				}

				catch (Exception ex) 
				{
					ta_chat.append("Cannot Connect! Try Again. \n");
					tf_username.setEditable(true);
				}

				ListenThread();
			}
			else if(username.contentEquals("neha") && password.contentEquals("test")) //user id and password for signing in the chat client application
			{
				try 
				{
					sock = new Socket(address, port);
					//InputStreamReader streamreader = new InputStreamReader(sock.getInputStream());
					//reader = new BufferedReader(streamreader);
					ois = new ObjectInputStream(sock.getInputStream());
					//writer = new PrintWriter(sock.getOutputStream());
					oos = new ObjectOutputStream(sock.getOutputStream());
					//writer.println(username + ":has connected.:Connect");
					oos.writeObject(username + ":has connected.:Connect");
					//writer.flush(); 
					oos.flush();
					isConnected = true; 
				}

				catch (Exception ex) 
				{
					ta_chat.append("Cannot Connect! Try Again. \n");
					tf_username.setEditable(true);
				}

				ListenThread();
			}
		} else if (isConnected == true) 
		{
			ta_chat.append("You are already connected. \n");
		}
	}//GEN-LAST:event_b_connectActionPerformed

	private void b_disconnectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_disconnectActionPerformed
		sendDisconnect();
		Disconnect();
	}//GEN-LAST:event_b_disconnectActionPerformed

	private void b_sendActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_sendActionPerformed
		String nothing = "";
		if ((tf_chat.getText()).equals(nothing)) {
			tf_chat.setText("");
			tf_chat.requestFocus();
		} else {
			try {
                                String sendMsg = username + ":" + tf_chat.getText();
                                byte[] encBytes = encrypt(sendMsg.getBytes(),myDesKey,xform);
				//writer.println(username + ":" + tf_chat.getText() + ":" + "Chat");
				//oos.writeObject(username + ":" + tf_chat.getText() + ":" + "Chat");
                                oos.writeObject(encBytes);
                                
                                
				//writer.flush(); // flushes the buffer
				oos.flush();
			} catch (Exception ex) {
                                ex.printStackTrace();
				ta_chat.append("Message was not sent. \n");
			}
			tf_chat.setText("");
			tf_chat.requestFocus();
		}

		tf_chat.setText("");
		tf_chat.requestFocus();
	}//GEN-LAST:event_b_sendActionPerformed

	private void tf_passwordActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_passwordActionPerformed
		// TODO add your handling code here:
	}//GEN-LAST:event_tf_passwordActionPerformed

	private void BuddyListActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_BuddyListActionPerformed
		// TODO add your handling code here:
		ta_chat.append("Buddy List \n");
		ta_chat.append("localhost 7001 \n local host 7002 \n localhost 7003 \n localhost 7004 \n localhost 7005");

	}//GEN-LAST:event_BuddyListActionPerformed

	public static void main(String args[]) 
	{
		java.awt.EventQueue.invokeLater(new Runnable() 
				{
					@Override
					public void run() 
					{
						new client_frame().setVisible(true);
					}
				});
	}

	// Variables declaration - do not modify//GEN-BEGIN:variables
	private javax.swing.JButton BuddyList;
	private javax.swing.JButton b_connect;
	private javax.swing.JButton b_disconnect;
	private javax.swing.JButton b_send;
	private javax.swing.JScrollPane jScrollPane1;
	private javax.swing.JLabel lb_address;
	private javax.swing.JLabel lb_password;
	private javax.swing.JLabel lb_port;
	private javax.swing.JLabel lb_username;
	private javax.swing.JTextArea ta_chat;
	private javax.swing.JTextField tf_address;
	private javax.swing.JTextField tf_chat;
	private javax.swing.JTextField tf_password;
	private javax.swing.JTextField tf_port;
	private javax.swing.JTextField tf_username;
	// End of variables declaration//GEN-END:variables
}
