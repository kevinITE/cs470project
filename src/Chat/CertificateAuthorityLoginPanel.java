//
//  CertificateAuthorityPanel.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  GUI class for the Certificate Authority Initialization.
//
package Chat;

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.swing.*;

public class CertificateAuthorityLoginPanel extends JPanel {

    JPasswordField _privateKeyPassField;
    JTextField _portField;
    JTextField _keystoreFileNameField;
    JLabel _errorLabel;
    JButton _startupButton;
    CertificateAuthority _ca;

    public CertificateAuthorityLoginPanel(CertificateAuthority ca) {
        _ca = ca;

        try {
            componentInit();
        } catch (Exception e) {
            System.out.println("CertificateAuthorityPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    void componentInit() throws Exception {
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();

        setLayout(gridBag);

        addLabel(gridBag, "Certificate Server Startup Panel", SwingConstants.CENTER,
                1, 0, 2, 1);
        addLabel(gridBag, "KeyStore File Path: ", SwingConstants.LEFT, 1, 1, 1, 1);
        addLabel(gridBag, "KeyStore Password: ", SwingConstants.LEFT, 1, 2, 1, 1);
        addLabel(gridBag, "Port Number: ", SwingConstants.LEFT, 1, 5, 1, 1);


        _keystoreFileNameField = new JTextField();
        addField(gridBag, _keystoreFileNameField, 2, 1, 1, 1);
        _keystoreFileNameField.setText("keystores/ks_CA");

        _privateKeyPassField = new JPasswordField();
        _privateKeyPassField.setEchoChar('*');
        addField(gridBag, _privateKeyPassField, 2, 2, 1, 1);
        _privateKeyPassField.setText("123456");

        _portField = new JTextField();
        addField(gridBag, _portField, 2, 5, 1, 1);
        _portField.setText("6666");

        _errorLabel = addLabel(gridBag, " ", SwingConstants.CENTER,
                1, 6, 2, 1);

        // just for testing purposs
        _errorLabel.setForeground(Color.red);

        _startupButton = new JButton("Start");
        c.gridx = 1;
        c.gridy = 8;
        c.gridwidth = 2;
        gridBag.setConstraints(_startupButton, c);
        add(_startupButton);

        _startupButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                try {
                    startup();
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        });
    }

    JLabel addLabel(GridBagLayout gridBag, String labelStr, int align,
            int x, int y, int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        JLabel label = new JLabel(labelStr);
        if (align == SwingConstants.LEFT) {
            c.anchor = GridBagConstraints.WEST;
        } else {
            c.insets = new Insets(10, 0, 10, 0);
        }
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(label, c);
        add(label);

        return label;
    }

    void addField(GridBagLayout gridBag, JTextField field, int x, int y,
            int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        field.setPreferredSize(new Dimension(96,
                field.getMinimumSize().height));
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(field, c);
        add(field);
    }

    private void startup() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        int _caPort;

        String _keystoreFileName = _keystoreFileNameField.getText();
        char[] _privateKeyPass = _privateKeyPassField.getPassword();

        if (_privateKeyPass.length == 0
                || _portField.getText().equals("")
                || _keystoreFileName.equals("")) {

            _errorLabel.setText("Missing required field.");

            return;

        } else {

            _errorLabel.setText(" ");

        }

        try {

            _caPort = Integer.parseInt(_portField.getText());

        } catch (NumberFormatException nfExp) {

            _errorLabel.setText("Port field is not numeric.");

            return;
        }

        switch (_ca.startup(_keystoreFileName,
                _privateKeyPass,
                _caPort)) {

            case CertificateAuthority.SUCCESS:
                //  Nothing happens, this panel is now hidden
                _errorLabel.setText(" ");
                break;
            case CertificateAuthority.KEYSTORE_FILE_NOT_FOUND:
                _errorLabel.setText("KeyStore file not found!");
                break;
            case CertificateAuthority.ERROR:
                _errorLabel.setText("Unknown Error!");
                break;
        }
    }
}
