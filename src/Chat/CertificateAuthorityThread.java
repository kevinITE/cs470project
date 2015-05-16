//
//  CertificateAuthorityThread.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Accepts connection requests and processes them
package Chat;

// socket

import java.net.*;
import java.io.*;

// Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class CertificateAuthorityThread extends Thread {

    private CertificateAuthority _ca;
    private ServerSocket _serverSocket = null;
    private int _portNum;
    private String _hostName;
    private JTextArea _outputArea;
    private KeyPair _keyPair;
    private String keyAlias = "client";
    private char[] keyStorePassword = "123456".toCharArray();

    public CertificateAuthorityThread(CertificateAuthority ca) {

        super("CertificateAuthorityThread");
        _ca = ca;
        _portNum = ca.getPortNumber();
        _outputArea = ca.getOutputArea();
        _serverSocket = null;

        try {

            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

        } catch (UnknownHostException e) {
            _hostName = "0.0.0.0";
        }
    }


    //  Accept connections and service them one at a time
    public void run() {

        try {

            _serverSocket = new ServerSocket(_portNum);

            _outputArea.append("CA waiting on " + _hostName + " port " + _portNum + "\n");

            while (true) {

                Socket socket = _serverSocket.accept();

                InputStream inStream = socket.getInputStream();
                OutputStream outStream = socket.getOutputStream();

                BufferedReader in = new BufferedReader(new InputStreamReader(inStream));
//                PrintWriter out = new PrintWriter(outStream, true);

                ObjectInputStream objIn = new ObjectInputStream(inStream);
                ObjectOutputStream objOut = new ObjectOutputStream(outStream);

                String username;
                String password;
                PublicKey publicKey;

                username = in.readLine();
                password = in.readLine();
                publicKey = (PublicKey) objIn.readObject();

                if(username != null && password != null && publicKey != null) {
                    // TODO: validate username password
                    _outputArea.append("Username: " + username + "\n");
                    _outputArea.append("Password: " + password + "\n");

                    X509Certificate cert = X509CertificateGenerator.generateCertificate("\"CN="+username+"\"", _ca._keyPair, 365, "SHA512withRSA");
                    objOut.writeObject(cert);
                }
            }
        } catch (Exception e) {
            System.out.println("CA thread error: " + e.getMessage());
            e.printStackTrace();
        }

    }
}
