package teamextension;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.text.BadLocationException;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.Base64;

public class BurpTeamPanel
extends JPanel {
	private static final long serialVersionUID = 1L;
    private boolean allMuted;
    private SharedValues sharedValues;
    private JButton startButton;
    private JTextField yourName;
    private JTextField theirPort;
    private JTextField theirAddress;
    private JTextField serverPassword;
    private JList<String> serverList;
    private JTextPane statusText;
    private JButton pauseButton;
    private JButton newRoom;
    private JButton leaveRoom;
    private JButton setScopeButton;
    private JButton getScopeButton;
    private JButton muteAllButton;
    private JButton saveConfigButton;
    private JCheckBox shareAllBurpMessages;
    private JCheckBox receiveCookies;
    private JCheckBox shareIssues;
    private JCheckBox receiveIssues;
    private JCheckBox shareCookies;
    private JLabel chosenCertKeyLabel;
    private JLabel chosenCertLabel;
    private JTabbedPane optionsPane;

    public BurpTeamPanel(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
        this.initComponents();
        this.allMuted = false;
        this.yourName.setText(this.sharedValues.getCallbacks().loadExtensionSetting("username"));
        this.theirAddress.setText(this.sharedValues.getCallbacks().loadExtensionSetting("servername"));
        this.theirPort.setText(this.sharedValues.getCallbacks().loadExtensionSetting("serverport"));
        this.serverPassword.setText(this.sharedValues.getCallbacks().loadExtensionSetting("serverpass"));
        if (this.sharedValues.getCallbacks().loadExtensionSetting("certificatePath") != null) {
            this.sharedValues.setCertFile(new File(this.sharedValues.getCallbacks().loadExtensionSetting("certificatePath")));
            this.chosenCertLabel.setText("Cert Set");
            this.sharedValues.setCertKeyFile(new File(this.sharedValues.getCallbacks().loadExtensionSetting("certificateKeyPath")));
            this.chosenCertKeyLabel.setText("Key Set");
            this.startButton.setEnabled(true);
        }
    }

    private void startButtonActionPerformed() {
        if (this.sharedValues.getClient() == null || !this.sharedValues.getClient().isConnected()) {
            // if we are not connected, connect
            if (this.sharedValues.connectToServer(
                    theirAddress.getText() + ":" + theirPort.getText(),
                    serverPassword.getText(),
                    yourName.getText())) {
                // if we connect successfully
                saveConfigButton.setEnabled(true);
                startButton.setText("Disconnect");
                newRoom.setEnabled(true);
            }
        } else {
            // if we are connected, leave
            if (sharedValues.getClient().isConnected()) {
                if (inRoom()) {
                    this.sharedValues.getClient().leaveRoom();
                }
                this.sharedValues.getClient().leaveServer();
            }
            resetConnectionUI();
        }
    }

    void resetConnectionUIWithReason(int reason) {
        resetConnectionUI();
        switch (reason) {
            case 401:
                writeToAlertPane("Failed to connect to server: Invalid " +
                        "password");
                break;
            case 409:
                writeToAlertPane("Failed to connect to server: Duplicate " +
                        "name on server");
                break;
            case -2:
                writeToAlertPane("Failed to connect to server: Malformed host");
                break;
            case -3:
                writeToAlertPane("Failed to connect to server: You didn't set" +
                        " the server cert/key files or they are incorrect.");
                break;
            case -4:
                writeToAlertPane("Failed to connect to server: invalid certificate or key.");
                break;
            case -5:
                writeToAlertPane("Failed to connect to server: connection refused. Is the port and host correct?");
                break;
            case -1:
                writeToAlertPane("Failed to connect to server: Unknown " +
                        "error");
                break;
            case 1:
                writeToAlertPane("Server crash");
                break;
            default:
                writeToAlertPane("Failed to connect to server: We " +
                        "shouldn't be here!!!");
                break;
        }
    }

    void writeToAlertPane(String message) {
        try {
            statusText.getDocument().insertString(0, message + "\n", null);
        } catch (BadLocationException e) {
            this.sharedValues.getCallbacks().printError(e.getMessage());
        }
    }

    private void readyToConnect() {
        if (this.startButton.getText().equals("Connect")) {
            this.startButton.setEnabled(false);
            if (this.chosenCertLabel.getText().length() == 0) {
                this.startButton.setToolTipText("make sure to import a server certificate");
            } else if (this.chosenCertKeyLabel.getText().length() == 0) {
                this.startButton.setToolTipText("make sure to import a server certificate key");
            } else if (this.yourName.getText().length() == 0) {
                this.startButton.setToolTipText("make sure to enter a name");
            } else if (this.theirAddress.getText().length() == 0) {
                this.startButton.setToolTipText("make sure to enter a server address");
            } else if (this.theirPort.getText().length() == 0) {
                this.startButton.setToolTipText("make sure to enter a server port");
            } else {
                this.startButton.setToolTipText("");
                this.startButton.setEnabled(true);
            }
        }
    }

    boolean inRoom() {
        return !this.newRoom.isEnabled();
    }

    private void resetConnectionUI() {
        sharedValues.getServerListModel().removeAllElements();

        allMuted = false;
        startButton.setText("Connect");
        saveConfigButton.setEnabled(false);
        newRoom.setEnabled(false);
        muteAllButton.setEnabled(false);
        setScopeButton.setEnabled(false);
        leaveRoom.setEnabled(false);
        pauseButton.setEnabled(false);
        getScopeButton.setEnabled(false);
    }

    JTabbedPane getOptionsPane() {
        return optionsPane;
    }

    private void initComponents() {
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{432, 435, 0};
        gridBagLayout.rowHeights = new int[]{149, 297, 0, 0};
        gridBagLayout.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
        setLayout(gridBagLayout);

        //info panel
        JPanel infoPanel = new JPanel();
        infoPanel.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                new SwingWorker<Boolean, Void>() {
                    @Override
                    public Boolean doInBackground() {
                        JTabbedPane burpTab = ((JTabbedPane) sharedValues.getBurpPanel().getParent());
                        JTabbedPane optionsPane = getOptionsPane();
                        if (optionsPane.getBackground().equals(new Color(0x3C3F41))) {
                            burpTab.setBackgroundAt(burpTab.indexOfTab(SharedValues.EXTENSION_NAME), new Color(0xBBBBBB));
                        } else {
                            burpTab.setBackgroundAt(burpTab.indexOfTab(SharedValues.EXTENSION_NAME), Color.black);
                        }
                        Timer timer = new Timer(3000, e -> {
                            if (optionsPane.getBackground().equals(new Color(0x3C3F41))) {
                                optionsPane.setBackgroundAt(optionsPane.indexOfTab("Comments"), new Color(0x3C3F41));
                            } else {
                                optionsPane.setBackgroundAt(optionsPane.indexOfTab("Comments"), Color.WHITE);
                            }

                        });
                        timer.setRepeats(false);
                        timer.start();
                        return Boolean.TRUE;
                    }

                    @Override
                    public void done() {
                        //we don't need to do any cleanup so this is empty
                    }
                }.execute();
            }

            @Override
            public void ancestorRemoved(AncestorEvent event) {

            }

            @Override
            public void ancestorMoved(AncestorEvent event) {

            }
        });
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.insets = new Insets(0, 0, 5, 5);
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        add(infoPanel, gridBagConstraints);
        infoPanel.setLayout(new GridLayout(1, 1, 0, 0));
        JLabel explainer = new JLabel();
        explainer.setHorizontalAlignment(SwingConstants.CENTER);
        infoPanel.add(explainer);
        explainer.setText("<html>Welcome to the Burp Suite Team " +
                "Collaborator! <br>This extension allows you to work in " +
                "tandem with multiple BurpSuite users by sharing their requests " +
                "with you. Any request that comes through their proxy will " +
                "show up in your site map as well.</html>\n");

        JPanel statusPanel = generatePanel(0, "Server Alerts");
        statusPanel.setLayout(new BorderLayout(0, 0));
        
        statusText = new JTextPane();
        statusText.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(statusText);
        statusPanel.add(scrollPane);
        //end info pane

        //connection panel
        JPanel connectionPanel = new JPanel();
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.insets = new Insets(0, 0, 5, 5);
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        add(connectionPanel, gridBagConstraints);
        connectionPanel.setLayout(new GridLayout(8, 2, 0, 0));
        JLabel yourNameLabel = new JLabel();
        connectionPanel.add(yourNameLabel);
        yourNameLabel.setText("Display Name:");
        this.yourName = new JTextField();
        this.yourName.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                readyToConnect();
            }

            @Override
            public void focusGained(FocusEvent e) {
                readyToConnect();
            }
        });
        connectionPanel.add(yourName);
        JLabel theirListenAddress = new JLabel();
        connectionPanel.add(theirListenAddress);
        theirListenAddress.setText("Server Address:");
        this.theirAddress = new JTextField();
        this.theirAddress.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                readyToConnect();
            }

            @Override
            public void focusGained(FocusEvent e) {
                readyToConnect();
            }
        });
        connectionPanel.add(theirAddress);
        JLabel theirListenPort = new JLabel();
        connectionPanel.add(theirListenPort);
        theirListenPort.setText("Server Port:");
        this.theirPort = new JTextField();
        this.theirPort.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                readyToConnect();
            }

            @Override
            public void focusGained(FocusEvent e) {
                readyToConnect();
            }
        });
        connectionPanel.add(theirPort);
        JLabel serverPasswordLabel = new JLabel();
        serverPasswordLabel.setText("Server Password:");
        connectionPanel.add(serverPasswordLabel);
        this.serverPassword = new JTextField();
        connectionPanel.add(this.serverPassword);
        this.startButton = new JButton();
        this.startButton.setEnabled(false);
        connectionPanel.add(startButton);
        this.startButton.setText("Connect");
        this.newRoom = new JButton("New Room");
        this.newRoom.addActionListener(actionEvent1 -> addRoomButtonActionPerformed());
        this.newRoom.setEnabled(false);
        connectionPanel.add(newRoom);
        this.pauseButton = new JButton();
        this.pauseButton.setEnabled(false);
        connectionPanel.add(pauseButton);
        this.pauseButton.setText("Pause");
        this.pauseButton.addActionListener(actionEvent1 -> pauseButtonActionPerformed());
        this.startButton.addActionListener(actionEvent1 -> startButtonActionPerformed());
        this.setScopeButton = new JButton("Set Room Scope");
        this.setScopeButton.addActionListener(actionEvent -> setScopeButtonActionPerformed());
        connectionPanel.add(this.setScopeButton);
        this.setScopeButton.setEnabled(false);
        this.leaveRoom = new JButton("Leave Room");
        this.leaveRoom.setEnabled(false);
        this.leaveRoom.addActionListener(actionEvent -> leaveRoomButtonActionPerformed());
        connectionPanel.add(leaveRoom);
        this.getScopeButton = new JButton("Get Room Scope");
        this.getScopeButton.setEnabled(false);
        this.getScopeButton.addActionListener(actionEvent -> getScopeButtonActionPerformed());
        connectionPanel.add(getScopeButton);
        this.muteAllButton = new JButton("Mute All");
        this.muteAllButton.setEnabled(false);
        this.muteAllButton.addActionListener(actionEvent -> muteAllButtonActionPerformed());
        connectionPanel.add(muteAllButton);
        this.saveConfigButton = new JButton("Save Server Config");
        this.saveConfigButton.setEnabled(false);
        this.saveConfigButton.addActionListener(e -> {
            this.sharedValues.getCallbacks().saveExtensionSetting("username", this.yourName.getText());
            this.sharedValues.getCallbacks().saveExtensionSetting("servername", this.theirAddress.getText());
            this.sharedValues.getCallbacks().saveExtensionSetting("serverport", this.theirPort.getText());
            this.sharedValues.getCallbacks().saveExtensionSetting("serverpass", this.serverPassword.getText());
            this.sharedValues.getCallbacks().saveExtensionSetting("certificatePath", sharedValues.getCertFile().getAbsolutePath());
            this.sharedValues.getCallbacks().saveExtensionSetting("certificateKeyPath", sharedValues.getCertKeyFile().getAbsolutePath());
        });
        connectionPanel.add(this.saveConfigButton);
        //end connection panel


        //rooms/members panel
        JPanel roomsPanel = generatePanel(1, "Rooms");
        roomsPanel.setLayout(new BorderLayout(2, 2));

        JPopupMenu roomMenu = new JPopupMenu();
        JMenuItem joinRoom = new JMenuItem("Join");
        joinRoom.addActionListener(e1 -> {
            this.sharedValues.getClient().joinRoom(serverList.getSelectedValue());
            this.newRoom.setEnabled(false);
            this.leaveRoom.setEnabled(true);
            this.pauseButton.setEnabled(true);
            this.getScopeButton.setEnabled(true);
            this.muteAllButton.setEnabled(true);
        });
        roomMenu.add(joinRoom);

        JPopupMenu clientMenu = new JPopupMenu();
        JMenuItem unmuteClient = new JMenuItem("Unmute");
        JMenuItem muteClient = new JMenuItem("Mute");
        muteClient.addActionListener(e1 -> {
            muteClient.setEnabled(false);
            unmuteClient.setEnabled(true);
            sharedValues.getClient().muteMember(serverList.getSelectedValue());
        });
        unmuteClient.addActionListener(e1 -> {
            unmuteClient.setEnabled(false);
            muteClient.setEnabled(true);
            sharedValues.getClient().unmuteMember(serverList.getSelectedValue());
        });
        unmuteClient.setEnabled(false);
        clientMenu.add(muteClient);
        clientMenu.add(unmuteClient);
        serverList = new JList<>();
        serverList.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    serverList.setSelectedIndex(serverList.locationToIndex(e.getPoint()));
                    if (!yourName.getText().equals(serverList.getSelectedValue())) {
                        if (sharedValues.getClient().getCurrentRoom().equals(
                                "server")) {
                            roomMenu.show(serverList, e.getPoint().x, e.getPoint().y);
                        } else {
                            if (!allMuted) {
                                sharedValues.getCallbacks().printOutput(serverList.getSelectedValue());
                                sharedValues.getCallbacks().printOutput(Boolean.toString(sharedValues.getClient().getMutedClients().contains(serverList.getSelectedValue())));
                                if (sharedValues.getClient().getMutedClients().contains(serverList.getSelectedValue())) {
                                    muteClient.setEnabled(false);
                                    unmuteClient.setEnabled(true);
                                } else {
                                    muteClient.setEnabled(true);
                                    unmuteClient.setEnabled(false);
                                }
                                clientMenu.show(serverList, e.getPoint().x, e.getPoint().y);
                            }
                        }
                    }
                }
            }
        });
        serverList.setModel(this.sharedValues.getServerListModel());
        serverList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        roomsPanel.add(serverList);
        //end rooms/members panel

        //bottom Tab Pane
        optionsPane = new JTabbedPane();
        GridBagConstraints optionsPanelConstraints = new GridBagConstraints();
        optionsPanelConstraints.fill = GridBagConstraints.BOTH;
        optionsPanelConstraints.gridwidth = 2;
        optionsPanelConstraints.gridx = 0;
        optionsPanelConstraints.gridy = 2;
        add(optionsPane, optionsPanelConstraints);
        //end bottom tab pane

        //shareable links
        JTable j = new JTable(this.sharedValues.getSharedLinksModel());
        j.setPreferredScrollableViewportSize(j.getPreferredSize());
        final JPopupMenu popupMenu = new JPopupMenu();
        popupMenu.addPopupMenuListener(new PopupMenuListener() {

            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                SwingUtilities.invokeLater(() -> {
                    int rowAtPoint = j.rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), j));
                    sharedValues.getCallbacks().printOutput(Integer.toString(rowAtPoint));
                    if (rowAtPoint > -1) {
                        j.setRowSelectionInterval(rowAtPoint, rowAtPoint);

                    }
                });
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                //this just isn't needed but I have to override it
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                //this just isn't needed but I have to override it
            }
        });
        JMenuItem removeLinkItem = new JMenuItem("Remove Link");
        removeLinkItem.addActionListener(e -> ((SharedLinksModel) j.getModel()).removeBurpMessage(j.getSelectedRow()));
        JMenuItem getHTMLLinkItem = new JMenuItem("Get HTML Link");
        getHTMLLinkItem.addActionListener(e -> {
            HttpRequestResponse burpMessage = ((SharedLinksModel) j.getModel()).getBurpMessageAtIndex(j.getSelectedRow());
            StringSelection stringSelection = new StringSelection(generateHTMLLink(burpMessage));
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            JOptionPane.showMessageDialog(null, "Link has been added to the clipboard");
        });
        JMenuItem getLinkItem = new JMenuItem("Get Link");
        getLinkItem.addActionListener(e -> {
            HttpRequestResponse burpMessage = ((SharedLinksModel) j.getModel()).getBurpMessageAtIndex(j.getSelectedRow());
            StringSelection stringSelection = new StringSelection("burptcmessage/" +
                    Base64.getEncoder().encodeToString(this.sharedValues.getGson().toJson(burpMessage).getBytes()));
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            JOptionPane.showMessageDialog(null, "Link has been added to the clipboard");
        });
        popupMenu.add(getLinkItem);
        popupMenu.add(getHTMLLinkItem);
        popupMenu.add(removeLinkItem);
        j.setComponentPopupMenu(popupMenu);
        JScrollPane sp = new JScrollPane(j);
        optionsPane.addTab("Shared Links", sp);
        //end shareable links

        //options panel
        JPanel optionsPanel = new JPanel(new GridLayout(5, 2));
        optionsPanel.setBorder(BorderFactory.createEmptyBorder(50, 50, 50, 50));

        final JFileChooser certFileChooser = new JFileChooser();
        chosenCertLabel = new JLabel();
        chosenCertLabel.setHorizontalAlignment(SwingConstants.CENTER);
        JButton chooseCertFile = new JButton("Select Certificate");
        chooseCertFile.setHorizontalAlignment(SwingConstants.CENTER);
        chooseCertFile.addActionListener(e -> {
            int returnVal =
                    certFileChooser.showOpenDialog(BurpTeamPanel.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                sharedValues.setCertFile(certFileChooser.getSelectedFile());
                chosenCertLabel.setText(certFileChooser.getSelectedFile().getName());
                readyToConnect();
            } else {
                sharedValues.getCallbacks().printOutput("Open command " +
                        "cancelled by user.");
            }
        });
        optionsPanel.add(chooseCertFile);
        optionsPanel.add(chosenCertLabel);

        final JFileChooser keyFileChooser = new JFileChooser();
        chosenCertKeyLabel = new JLabel();
        chosenCertKeyLabel.setHorizontalAlignment(SwingConstants.CENTER);
        JButton chooseCertKey = new JButton("Select Certificate Key");
        chooseCertKey.setHorizontalAlignment(SwingConstants.CENTER);
        chooseCertKey.addActionListener(e -> {
            int returnVal =
                    keyFileChooser.showOpenDialog(BurpTeamPanel.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                sharedValues.setCertKeyFile(keyFileChooser.getSelectedFile());
                chosenCertKeyLabel.setText(keyFileChooser.getSelectedFile().getName());
                readyToConnect();
            } else {
                sharedValues.getCallbacks().printOutput("Open command " +
                        "cancelled by user.");
            }
        });
        optionsPanel.add(chooseCertKey);
        optionsPanel.add(chosenCertKeyLabel);

        shareAllBurpMessages = new JCheckBox("Share all requests");
        shareAllBurpMessages.setHorizontalAlignment(SwingConstants.CENTER);
        shareAllBurpMessages.setSelected(true);
        optionsPanel.add(shareAllBurpMessages);

        shareCookies = new JCheckBox("Share Cookies");
        shareCookies.setHorizontalAlignment(SwingConstants.CENTER);
        shareCookies.setSelected(true);
        optionsPanel.add(shareCookies);

        receiveCookies = new JCheckBox("Receive Shared Cookies");
        receiveCookies.setHorizontalAlignment(SwingConstants.CENTER);
        receiveCookies.setSelected(true);
        optionsPanel.add(receiveCookies);

        shareIssues = new JCheckBox("Share Issues");
        shareIssues.setHorizontalAlignment(SwingConstants.CENTER);
        shareIssues.setSelected(true);
        optionsPanel.add(shareIssues);

        receiveIssues = new JCheckBox("Receive Shared Issues");
        receiveIssues.setHorizontalAlignment(SwingConstants.CENTER);
        receiveIssues.setSelected(true);
        optionsPanel.add(receiveIssues);
        optionsPane.addTab("Configuration", optionsPanel);
        //end options panel

        //comments panel
        JList<HttpRequestResponse> commentsList = new JList<>();
        commentsList.setModel(sharedValues.getRequestCommentModel());
        commentsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        commentsList.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent evt) {
                JList list = (JList) evt.getSource();
                if (evt.getClickCount() == 2) {
                    int index = list.locationToIndex(evt.getPoint());
                    new CommentFrame(sharedValues, ((RequestCommentModel) commentsList.getModel()).getTrueElementAt(index),
                            sharedValues.getClient().getUsername());
                }
            }
        });
        JScrollPane commentsScrollPane = new JScrollPane(commentsList);
        commentsScrollPane.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                new SwingWorker<Boolean, Void>() {
                    @Override
                    public Boolean doInBackground() {
                        JTabbedPane optionsPane = getOptionsPane();
                        if (optionsPane.getBackground().equals(new Color(0x3C3F41))) {
                            optionsPane.setBackgroundAt(optionsPane.indexOfTab("Comments"), new Color(0xBBBBBB));
                        } else {
                            optionsPane.setBackgroundAt(optionsPane.indexOfTab("Comments"), Color.black);
                        }
                        return Boolean.TRUE;
                    }

                    @Override
                    public void done() {
                        //we don't need to do any cleanup so this is empty
                    }
                }.execute();
            }

            @Override
            public void ancestorRemoved(AncestorEvent event) {

            }

            @Override
            public void ancestorMoved(AncestorEvent event) {

            }
        });
        optionsPane.addTab("Comments", commentsScrollPane);
        //end comments panel

    }

    boolean getShareAllRequestsSetting() {
        return shareAllBurpMessages.isSelected();
    }

    boolean getShareCookiesSetting() {
        return shareCookies.isSelected();
    }

    boolean getReceiveSharedCookiesSetting() {
        return receiveCookies.isSelected();
    }

    boolean getShareIssuesSetting() {
        return shareIssues.isSelected();
    }

    boolean getReceiveSharedIssuesSetting() {
        return receiveIssues.isSelected();
    }

    private void muteAllButtonActionPerformed() {
        if (this.allMuted) {
            this.muteAllButton.setText("Mute All");
            sharedValues.getClient().unmuteAllMembers();
        } else {
            this.muteAllButton.setText("Unmute All");
            sharedValues.getClient().muteAllMembers();
        }
        this.allMuted = !this.allMuted;
    }

    private void getScopeButtonActionPerformed() {
        this.sharedValues.getClient().getRoomScope();
    }

    private void setScopeButtonActionPerformed() {
        this.sharedValues.getClient().setRoomScope();
    }

    private void leaveRoomButtonActionPerformed() {
        sharedValues.getServerListModel().removeAllElements();
        this.allMuted = false;
        this.newRoom.setEnabled(true);
        this.muteAllButton.setEnabled(false);
        this.setScopeButton.setEnabled(false);
        this.leaveRoom.setEnabled(false);
        this.pauseButton.setEnabled(false);
        this.getScopeButton.setEnabled(false);
        this.sharedValues.getClient().leaveRoom();
    }

    private void addRoomButtonActionPerformed() {
        JDialog roomOptions = new JDialog();
        roomOptions.setTitle("Room Options");
        JTextField roomName = new JTextField();
        roomOptions.add(roomName);
        String roomNameValue = JOptionPane.showInputDialog(roomOptions, "Please enter a room name");
        this.sharedValues.getCallbacks().printOutput(roomNameValue);
        if ((roomNameValue != null) && (roomNameValue.length() > 0)) {
            sharedValues.getServerListModel().removeAllElements();
            this.sharedValues.getClient().createRoom(roomNameValue);
            this.muteAllButton.setEnabled(true);
            this.setScopeButton.setEnabled(true);
            this.newRoom.setEnabled(false);
            this.leaveRoom.setEnabled(true);
            this.pauseButton.setEnabled(true);
        }
    }

    private void pauseButtonActionPerformed() {
        if (this.sharedValues.getClient().isPaused()) {
            this.sharedValues.getClient().unpauseCommunication();
            this.pauseButton.setText("Pause");
        } else {
            this.sharedValues.getClient().pauseCommunication();
            this.pauseButton.setText("Unpause");
        }
    }

    private String generateHTMLLink(HttpRequestResponse burpMessage) {
        return "<a href='http://burptcmessage/" +
                Base64.getEncoder().encodeToString(this.sharedValues.getGson().toJson(burpMessage).getBytes())
                + "'>" + this.sharedValues.getCallbacks().getHelpers().analyzeRequest(burpMessage).getUrl().toString()
                + "</a>";
    }

    private JPanel generatePanel(int yLocation, String name) {
        JPanel panel = new JPanel();
        panel.setBorder(new TitledBorder(name));
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yLocation;
        add(panel, gridBagConstraints);
        return panel;
    }
}
