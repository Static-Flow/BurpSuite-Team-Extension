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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

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
    private JList<Room> serverList;
    private JList<String> roomMemberList;
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
    private JPanel roomsPanel;

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

    void enableRoomControl() {
        this.setScopeButton.setEnabled(true);
        this.getScopeButton.setEnabled(false);
    }

    private void startButtonActionPerformed() {
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                if (sharedValues.getClient() == null || !sharedValues.getClient().isConnected()) {
                    // if we are not connected, connect
                    if (sharedValues.connectToServer(
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
                    sharedValues.getRoomMembersListModel().removeAllElements();
                    sharedValues.getServerListModel().removeAllElements();
                    sharedValues.getSharedLinksModel().removeAllElements();
                    if (sharedValues.getClient().isConnected()) {
                        sharedValues.getClient().leaveServer();
                    }
                    resetConnectionUI();

                    sharedValues.closeCommentSessions();
                }
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
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
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                try {
                    statusText.getDocument().insertString(0, message + "\n", null);
                } catch (BadLocationException e) {
                    sharedValues.getCallbacks().printError(e.getMessage());
                }
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
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
        writeToAlertPane("Disconnected from server");
        this.swapServerAndRoomLists(false);
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
                                optionsPane.setForegroundAt(optionsPane.indexOfTab("Comments"), new Color(0xBBBBBB));
                            } else {
                                optionsPane.setForegroundAt(optionsPane.indexOfTab("Comments"), Color.black);
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
        roomsPanel = generatePanel(1, "Rooms");
        roomsPanel.setLayout(new CardLayout(2, 2));

        JPopupMenu roomMenu = new JPopupMenu();
        JMenuItem joinRoom = new JMenuItem("Join");
        joinRoom.addActionListener(e1 -> {
                new SwingWorker<Boolean, Void>() {
                    @Override
                    public Boolean doInBackground() {
                        if (serverList.getSelectedValue().hasPassword()) {
                            JDialog roomOptions = new JDialog();
                            roomOptions.setTitle("Enter Room Password");
                            JTextField roomPassword = new JTextField();
                            roomOptions.add(roomPassword);
                            String roomPasswordValue = JOptionPane.showInputDialog(roomOptions, "Please enter room password");
                            sharedValues.getCallbacks().printOutput(roomPasswordValue);
                            if ((roomPasswordValue != null) && (roomPasswordValue.length() > 0)) {
                                sharedValues.getClient().checkRoomPassword(serverList.getSelectedValue().getRoomName(), roomPasswordValue);
                            } else {
                                writeToAlertPane("Please supply a password for the room.");
                            }
                        } else {
                            joinRoom();
                        }
                        return Boolean.TRUE;
                    }

                    @Override
                    public void done() {
                        //we don't need to do any cleanup so this is empty
                    }
                }.execute();
        });
        roomMenu.add(joinRoom);

        JPopupMenu clientMenu = new JPopupMenu();
        JMenuItem unmuteClient = new JMenuItem("Unmute");
        JMenuItem muteClient = new JMenuItem("Mute");
        muteClient.addActionListener(e1 -> {
            muteClient.setEnabled(false);
            unmuteClient.setEnabled(true);
            sharedValues.getClient().muteMember(roomMemberList.getSelectedValue());
        });
        unmuteClient.addActionListener(e1 -> {
            unmuteClient.setEnabled(false);
            muteClient.setEnabled(true);
            sharedValues.getClient().unmuteMember(roomMemberList.getSelectedValue());
        });
        unmuteClient.setEnabled(false);
        clientMenu.add(muteClient);
        clientMenu.add(unmuteClient);

        roomMemberList = new JList<>();
        roomMemberList.setModel(sharedValues.getRoomMembersListModel());
        roomMemberList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        roomMemberList.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    if (!allMuted) {
                        if (!roomMemberList.getModel().getElementAt(roomMemberList.locationToIndex(e.getPoint())).equals(yourName.getText())) {
                            roomMemberList.setSelectedIndex(roomMemberList.locationToIndex(e.getPoint()));
                            sharedValues.getCallbacks().printOutput(roomMemberList.getSelectedValue());
                            sharedValues.getCallbacks().printOutput(Boolean.toString(sharedValues.getClient().getMutedClients().contains(roomMemberList.getSelectedValue())));
                            if (sharedValues.getClient().getMutedClients().contains(roomMemberList.getSelectedValue())) {
                                muteClient.setEnabled(false);
                                unmuteClient.setEnabled(true);
                            } else {
                                muteClient.setEnabled(true);
                                unmuteClient.setEnabled(false);
                            }
                            clientMenu.show(roomMemberList, e.getPoint().x, e.getPoint().y);
                        }
                    }
                }
            }
        });

        serverList = new JList<>();
        serverList.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    if (serverList.getModel().getSize() > 0) {
                        serverList.setSelectedIndex(serverList.locationToIndex(e.getPoint()));
                        roomMenu.show(serverList, e.getPoint().x, e.getPoint().y);
                    }
                }
            }
        });
        serverList.setModel(this.sharedValues.getServerListModel());
        serverList.setCellRenderer(new ServerListCustomCellRenderer());
        serverList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        roomsPanel.add(serverList, "rooms");
        roomsPanel.add(roomMemberList, "members");
        ((CardLayout) (this.roomsPanel.getLayout())).show(roomsPanel, "rooms");
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
            StringSelection stringSelection = null;
            try {
                stringSelection = new StringSelection(
                        "burptcmessage/" +
                            Base64.getEncoder().encodeToString(compress(this.sharedValues.getGson().toJson(burpMessage))));
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            this.sharedValues.getCallbacks().printOutput(stringSelection.toString());
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
                    CommentFrame commentSession = new CommentFrame(sharedValues,
                            ((RequestCommentModel) commentsList.getModel()).getTrueElementAt(index),
                            sharedValues.getClient().getUsername());
                    sharedValues.getRequestCommentModel().addCommentSession(commentSession);
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
                        JTabbedPane burpTab = ((JTabbedPane) sharedValues.getBurpPanel().getParent());
                        JTabbedPane optionsPane = getOptionsPane();
                        if (optionsPane.getBackground().equals(new Color(0x3C3F41))) {
                            burpTab.setBackgroundAt(burpTab.indexOfTab(SharedValues.EXTENSION_NAME), new Color(0xBBBBBB));
                        } else {
                            burpTab.setBackgroundAt(burpTab.indexOfTab(SharedValues.EXTENSION_NAME), Color.black);
                        }
                        if (optionsPane.getBackground().equals(new Color(0x3C3F41))) {
                            optionsPane.setForegroundAt(optionsPane.indexOfTab("Comments"), new Color(0xBBBBBB));
                        } else {
                            optionsPane.setForegroundAt(optionsPane.indexOfTab("Comments"), Color.black);
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

    void swapServerAndRoomLists(boolean toRoom) {
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                sharedValues.getCallbacks().printOutput("resetting room/server list");
                CardLayout cardLayout = (CardLayout) (roomsPanel.getLayout());
                if (toRoom) {
                    ((TitledBorder) roomsPanel.getBorder()).setTitle("Room Members");
                    cardLayout.show(roomsPanel, "members");
                } else {
                    ((TitledBorder) roomsPanel.getBorder()).setTitle("Rooms");
                    cardLayout.show(roomsPanel, "rooms");
                }
                roomsPanel.repaint();
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
    }

    private static byte[] compress(String data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length());
        GZIPOutputStream gzip = new GZIPOutputStream(bos);
        gzip.write(data.getBytes());
        gzip.close();
        byte[] compressed = bos.toByteArray();
        bos.close();
        return compressed;
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
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                swapServerAndRoomLists(false);
                allMuted = false;
                newRoom.setEnabled(true);
                muteAllButton.setEnabled(false);
                setScopeButton.setEnabled(false);
                leaveRoom.setEnabled(false);
                pauseButton.setEnabled(false);
                getScopeButton.setEnabled(false);
                sharedValues.getClient().leaveRoom();
                sharedValues.closeCommentSessions();
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
    }

    private void addRoomButtonActionPerformed() {
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                JFrame addRoomFrame = new JFrame("Room Options");
                addRoomFrame.setLayout(new BorderLayout());
                JPanel topPane = new JPanel(new GridBagLayout());
                GridBagConstraints c = new GridBagConstraints();
                JLabel errorString = new JLabel(" ");
                JLabel roomNameLabel = new JLabel("Room Name:      ");
                roomNameLabel.setHorizontalAlignment(SwingConstants.LEFT);
                JTextField roomName = new JTextField(25);
                roomName.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseEntered(MouseEvent e) {
                        errorString.setText(" ");
                    }
                });
                JLabel roomPasswordLabel = new JLabel(" Room Password: ");
                roomPasswordLabel.setHorizontalAlignment(SwingConstants.LEFT);
                JTextField roomPassword = new JTextField(25);
                JButton submit = new JButton("Create Room");
                submit.addActionListener(e -> {
                    sharedValues.getCallbacks().printOutput(roomName.getText());
                    if (roomName.getText().length() > 0) {
                        swapServerAndRoomLists(true);
                        sharedValues.getClient().createRoom(roomName.getText(), roomPassword.getText());
                        muteAllButton.setEnabled(true);
                        setScopeButton.setEnabled(true);
                        newRoom.setEnabled(false);
                        leaveRoom.setEnabled(true);
                        pauseButton.setEnabled(true);
                        addRoomFrame.dispose();
                    } else {
                        errorString.setText("Invalid Room name");
                    }

                });
                c.gridx = 0;
                c.gridy = 0;
                c.gridwidth = 2;
                c.fill = GridBagConstraints.HORIZONTAL;
                topPane.add(errorString);
                c.gridx = 0;
                c.gridy = 1;
                c.gridwidth = 1;
                c.weightx = 0;
                topPane.add(roomNameLabel, c);
                c.gridx = 1;
                c.gridy = 1;
                c.weightx = 1;
                topPane.add(roomName, c);
                c.gridx = 0;
                c.gridy = 2;
                c.weightx = 0;
                topPane.add(roomPasswordLabel, c);
                c.gridx = 1;
                c.gridy = 2;
                c.weightx = 1;
                topPane.add(roomPassword, c);
                c.gridwidth = 2;
                c.gridx = 0;
                c.gridy = 3;
                c.fill = GridBagConstraints.HORIZONTAL;
                topPane.add(submit, c);
                addRoomFrame.add(topPane);
                addRoomFrame.setSize(400, 310);
                addRoomFrame.pack();
                addRoomFrame.setVisible(true);
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
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

    void joinRoom() {
        this.sharedValues.getClient().joinRoom(serverList.getSelectedValue().getRoomName());
        this.newRoom.setEnabled(false);
        this.leaveRoom.setEnabled(true);
        this.pauseButton.setEnabled(true);
        this.getScopeButton.setEnabled(true);
        this.muteAllButton.setEnabled(true);
        this.swapServerAndRoomLists(true);
    }

    JPanel getRoomsPanel() {
        return this.roomsPanel;
    }
}
