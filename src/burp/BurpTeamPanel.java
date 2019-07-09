/*
 * Decompiled with CFR 0.139.
 * 
 * Could not load the following classes:
 *  burp.ServerConnector
 */
package burp;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class BurpTeamPanel
extends JPanel {
	private static final long serialVersionUID = 1L;
	private SharedValues sharedValues;
    private JLabel Explainer;
    private JButton StartButton;
    private JLabel yourNameLabel;
    private JTextField yourName;
    private JLabel theirListenPort;
    private JTextField theirPort;
    private JLabel TheirListenAddress;
    private JTextField theirAddress;
    private JPanel infoPanel;
    private JPanel connectionPanel;
    private JPanel actionPanel;
    private JList serverList;
    private JPanel panel;
    private JTextPane statusText;
    private JButton PauseButton;

    public BurpTeamPanel(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
        this.initComponents();
    }

    private void StartButtonActionPerformed(ActionEvent actionEvent) {
        if (this.sharedValues.isCommunicating()) {
            this.StartButton.setText("Connect");
            this.sharedValues.stopCommunication();
            try {
                this.statusText.getDocument().insertString(this.statusText.getDocument().getLength(), "Disconnected from server\n", null);
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
        } else {
            this.StartButton.setText("Disconnect");
            this.sharedValues.setServerConnection(new ServerConnector(this.theirAddress.getText(),
                    Integer.parseInt(this.theirPort.getText()), this.yourName.getText(),
                    this.sharedValues.getStderr(), this.sharedValues));
            try {
                if (this.sharedValues.getServerConnection().getSocket().isConnected()) {
                    this.sharedValues.startCommunication();
                    this.statusText.getDocument().insertString(this.statusText.getDocument().getLength(), "Connected to server\n", null);
                }
            } catch (BadLocationException e) {
                System.out.println("error" + e);
            }
        }
    }

    private void initComponents() {
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{432, 435, 0};
        gridBagLayout.rowHeights = new int[]{149, 297, 0, 0};
        gridBagLayout.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
        setLayout(gridBagLayout);
        
        infoPanel = new JPanel();
        GridBagConstraints gbc_infoPanel = new GridBagConstraints();
        gbc_infoPanel.fill = GridBagConstraints.BOTH;
        gbc_infoPanel.insets = new Insets(0, 0, 5, 5);
        gbc_infoPanel.gridx = 0;
        gbc_infoPanel.gridy = 0;
        add(infoPanel, gbc_infoPanel);
        infoPanel.setLayout(new GridLayout(1, 1, 0, 0));
        this.Explainer = new JLabel();
        Explainer.setHorizontalAlignment(SwingConstants.CENTER);
        infoPanel.add(Explainer);
        this.Explainer.setText("<html>Welcome to the BurpSuite Team " +
                "Collaborator! <br>This extension allows you to work in " +
                "tandem with multiple BurpSuite users by sharing their requests " +
                "with you. Any request that comes through their proxy will " +
                "show up in your site map as well.</html>\n");
        
        panel = new JPanel();
        GridBagConstraints gbc_panel = new GridBagConstraints();
        gbc_panel.insets = new Insets(0, 0, 5, 0);
        gbc_panel.fill = GridBagConstraints.BOTH;
        gbc_panel.gridx = 1;
        gbc_panel.gridy = 0;
        add(panel, gbc_panel);
        panel.setLayout(new BorderLayout(0, 0));
        
        statusText = new JTextPane();
        panel.add(statusText);
        
        connectionPanel = new JPanel();
        GridBagConstraints gbc_connectionPanel = new GridBagConstraints();
        gbc_connectionPanel.fill = GridBagConstraints.BOTH;
        gbc_connectionPanel.insets = new Insets(0, 0, 5, 5);
        gbc_connectionPanel.gridx = 0;
        gbc_connectionPanel.gridy = 1;
        add(connectionPanel, gbc_connectionPanel);
        connectionPanel.setLayout(new GridLayout(6, 2, 0, 0));
        this.yourNameLabel = new JLabel();
        connectionPanel.add(yourNameLabel);
        this.yourNameLabel.setText("Display Name:");
        this.yourName = new JTextField();
        connectionPanel.add(yourName);
        this.TheirListenAddress = new JLabel();
        connectionPanel.add(TheirListenAddress);
        this.TheirListenAddress.setText("Server Address:");
        this.theirAddress = new JTextField();
        connectionPanel.add(theirAddress);
        this.theirListenPort = new JLabel();
        connectionPanel.add(theirListenPort);
        this.theirListenPort.setText("Server Port:");
        this.theirPort = new JTextField();
        connectionPanel.add(theirPort);
        this.StartButton = new JButton();
        connectionPanel.add(StartButton);
        this.StartButton.setText("Connect");
        this.PauseButton = new JButton();
        connectionPanel.add(PauseButton);
        this.PauseButton.setText("Pause");
        this.PauseButton.addActionListener(this::PauseButtonActionPerformed);
        this.StartButton.addActionListener(this::StartButtonActionPerformed);
        
        actionPanel = new JPanel();
        GridBagConstraints gbc_actionPanel = new GridBagConstraints();
        gbc_actionPanel.insets = new Insets(0, 0, 5, 0);
        gbc_actionPanel.fill = GridBagConstraints.BOTH;
        gbc_actionPanel.gridx = 1;
        gbc_actionPanel.gridy = 1;
        add(actionPanel, gbc_actionPanel);
        actionPanel.setLayout(new BorderLayout(2, 2));

        JPopupMenu menu = new JPopupMenu();
        JMenuItem unmuteClient = new JMenuItem("Unmute");
        JMenuItem muteClient = new JMenuItem("Mute");
        muteClient.addActionListener(e1 -> {
            muteClient.setVisible(false);
            unmuteClient.setVisible(true);
            sharedValues.getServerConnection().muteMember((String) serverList.getSelectedValue());
        });
        unmuteClient.addActionListener(e1 -> {
            unmuteClient.setVisible(false);
            muteClient.setVisible(true);
            sharedValues.getServerConnection().unmuteMember((String) serverList.getSelectedValue());
        });
        unmuteClient.setVisible(false);
        menu.add(muteClient);
        menu.add(unmuteClient);
        serverList = new JList();
        serverList.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    serverList.setSelectedIndex(serverList.locationToIndex(e.getPoint()));
                    menu.show(serverList, e.getPoint().x, e.getPoint().y);
                }
            }
        });
        serverList.setModel(this.sharedValues.getServerListModel());
        serverList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        actionPanel.add(serverList);
    }

    private void PauseButtonActionPerformed(ActionEvent actionEvent) {
        if (this.sharedValues.isCommunicating()) {
            this.sharedValues.pauseCommunication();
            this.PauseButton.setText("Unpause");
        } else {
            this.sharedValues.unpauseCommunication();
            this.PauseButton.setText("Pause");
        }
    }
}
