//
//  CertificateAuthority.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
package Chat;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

public class CertificateAuthority {

    public static final int SUCCESS = 0;
    public static final int KEYSTORE_FILE_NOT_FOUND = 1;
    public static final int ERROR = 4;
    private int _portNum;
    CertificateAuthorityLoginPanel _panel;
    CertificateAuthorityActivityPanel _activityPanel;
    CardLayout _layout;
    JFrame _appFrame;
    CertificateAuthorityThread _thread;
    KeyStore _keyStore;
    String _ksFileName;
    char[] _privateKeyPass;
    KeyPair _keyPair;


    public CertificateAuthority() throws Exception {

        _panel = null;
        _activityPanel = null;
        _layout = null;
        _appFrame = null;

        try {
            initialize();
        } catch (Exception e) {
            System.out.println("CA error: " + e.getMessage());
            e.printStackTrace();
        }

        _layout.show(_appFrame.getContentPane(), "CAPanel");

    }

    //  initialize
    //  
    //  CA initialization
    private void initialize() throws Exception {

        _appFrame = new JFrame("Certificate Authority");
        _layout = new CardLayout();

        _appFrame.getContentPane().setLayout(_layout);
        _panel = new CertificateAuthorityLoginPanel(this);
        _appFrame.getContentPane().add(_panel, "CAPanel");

        _activityPanel = new CertificateAuthorityActivityPanel(this);
        _appFrame.getContentPane().add(_activityPanel, "ActivityPanel");

        _appFrame.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        });
    }

    public void run() {
        _appFrame.pack();
        _appFrame.setVisible(true);
    }

    //  quit
    //
    //  Called when the application is about to quit.
    public void quit() {

        try {
            System.out.println("quit called");
        } catch (Exception err) {
            System.out.println("CertificateAuthority error: " + err.getMessage());
            err.printStackTrace();
        }

        System.exit(0);
    }

    //
    //  Start up the CA server
    //
    public int startup(String _ksFileName,
                       char[] _privateKeyPass,
                       int _caPort) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

        _portNum = _caPort;

        this._ksFileName = _ksFileName;
        this._privateKeyPass = _privateKeyPass;
        FileInputStream keyStoreStream = new FileInputStream(new File(_ksFileName));
        _keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keyStore.load(keyStoreStream, _privateKeyPass);
        PrivateKey privateKey = (PrivateKey) _keyStore.getKey("root", _privateKeyPass);
        Certificate cert = _keyStore.getCertificate("root");
        _keyPair = new KeyPair(cert.getPublicKey(), privateKey);


        _layout.show(_appFrame.getContentPane(), "ActivityPanel");

        _thread = new CertificateAuthorityThread(this);
        _thread.start();
        return CertificateAuthority.SUCCESS;

    }

    public int getPortNumber() {

        return _portNum;
    }

    public JTextArea getOutputArea() {

        return _activityPanel.getOutputArea();
    }

    public static void main(String[] args) throws Exception {

        CertificateAuthority ca = new CertificateAuthority();
        ca.run();
    }
}
