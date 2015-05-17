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
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class CertificateAuthorityThread extends Thread {

    private CertificateAuthority _ca;
    private ServerSocket _serverSocket = null;
    private int _portNum;
    private String _hostName;
    private JTextArea _outputArea;

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

                    OutputStream outStream = socket.getOutputStream();
                    InputStream inStream = socket.getInputStream();
                    ObjectOutputStream out = new ObjectOutputStream(outStream);
                    ObjectInputStream in = new ObjectInputStream(inStream);

                    PackageRegister packageRegister = (PackageRegister) in.readObject();

                    if(packageRegister != null) {
                        _outputArea.append("Registration request: " + packageRegister.username + "\n");

                        Certificate existingCert = _ca._keyStore.getCertificate(packageRegister.username);
                        X509Certificate cert = null;

                        if(existingCert == null) {
                            cert = X509CertificateGenerator.generateCertificate("CN="+ packageRegister.username, _ca._keyPair, 365, "SHA256withRSA");

                            // save the certificate
                            _ca._keyStore.setCertificateEntry(packageRegister.username, cert);
                            FileOutputStream keyStoreStream = new FileOutputStream(new File(_ca._ksFileName));
                            _ca._keyStore.store(keyStoreStream, _ca._privateKeyPass);

                            _outputArea.append("A new certificate is created and sent. Registration completed.");
                        }
                        else {
                            _outputArea.append("Username is already in use.");
                        }

                        // send certificate to the client

                        out.writeObject(cert);
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
