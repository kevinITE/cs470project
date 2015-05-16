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

                try {
                    Socket socket = _serverSocket.accept();

                    InputStream inStream = socket.getInputStream();
                    OutputStream outStream = socket.getOutputStream();

                    ObjectInputStream objIn = new ObjectInputStream(inStream);
                    CertRequest certRequest = (CertRequest) objIn.readObject();

                    if(certRequest != null) {
                        // TODO: validate username password
                        _outputArea.append("Username: " + certRequest.username + "\n");
                        _outputArea.append("Password: " + certRequest.password + "\n");

                        X509Certificate cert = X509CertificateGenerator.generateCertificate("CN="+certRequest.username, _ca._keyPair, 365, "SHA512withRSA");
                        ObjectOutputStream objOut = new ObjectOutputStream(outStream);
                        objOut.writeObject(cert);
                    }
                } catch (Exception e) {
                    System.out.println("Client connection error: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            System.out.println("CA thread error: " + e.getMessage());
            e.printStackTrace();
        }

    }
}
