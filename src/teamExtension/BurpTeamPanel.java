package teamExtension;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.text.BadLocationException;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
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

    public BurpTeamPanel(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
        this.initComponents();
        this.allMuted = false;
        this.theirAddress.setText(this.sharedValues.getCallbacks().loadExtensionSetting("servername"));
        this.theirPort.setText(this.sharedValues.getCallbacks().loadExtensionSetting("serverport"));
        this.serverPassword.setText(this.sharedValues.getCallbacks().loadExtensionSetting("serverpass"));
    }

    private void StartButtonActionPerformed() {
        if (this.sharedValues.isCommunicating()) {
            this.sharedValues.stopCommunication();
        } else {
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    sharedValues.setServerConnection(new ServerConnector(theirAddress.getText(),
                            Integer.parseInt(theirPort.getText()),
                            yourName.getText(), serverPassword.getText(), sharedValues));
                    try {
                        try {
                            sharedValues.getServerConnection().authenticate();
                            sharedValues.getServerConnection().getServerRooms();
                            saveConfigButton.setEnabled(true);
                            startButton.setText("Disconnect");
                            newRoom.setEnabled(true);
                            sharedValues.startCommunication();
                            statusText.getDocument().insertString(
                                    statusText.getDocument().getLength(),
                                    "Connected to server\n", null);
                        } catch (LoginFailedException e) {
                            statusText.getDocument().insertString(
                                    statusText.getDocument().getLength(),
                                    "Incorrect Password\n", null);
                            return Boolean.TRUE;
                        } catch (IOException e) {
                            statusText.getDocument().insertString(
                                    statusText.getDocument().getLength(),
                                    "Server connection timeout\n", null);
                            return Boolean.TRUE;
                        }
                    } catch (BadLocationException e) {
                        System.out.println("error" + e);
                    }
                    try {
                        sharedValues.getServerConnection().getListener().join();
                        System.out.println("Client done listening");
                    } catch (InterruptedException e) {
                        return Boolean.TRUE;
                    }
                    return Boolean.TRUE;
                }

                @Override
                public void done() {
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
                    try {
                        statusText.getDocument().insertString(
                                statusText.getDocument().getLength(),
                                "Disconnected from server\n", null);
                    } catch (BadLocationException e) {
                        e.printStackTrace();
                    }
                }
            }.execute();
        }
    }

    private void initComponents() {
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{432, 435, 0};
        gridBagLayout.rowHeights = new int[]{149, 297, 0, 0};
        gridBagLayout.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
        setLayout(gridBagLayout);

        JPanel infoPanel = new JPanel();
        GridBagConstraints gbc_infoPanel = new GridBagConstraints();
        gbc_infoPanel.fill = GridBagConstraints.BOTH;
        gbc_infoPanel.insets = new Insets(0, 0, 5, 5);
        gbc_infoPanel.gridx = 0;
        gbc_infoPanel.gridy = 0;
        add(infoPanel, gbc_infoPanel);
        infoPanel.setLayout(new GridLayout(1, 1, 0, 0));
        JLabel explainer = new JLabel();
        explainer.setHorizontalAlignment(SwingConstants.CENTER);
        infoPanel.add(explainer);
        explainer.setText("<html>Welcome to the Burp Suite Team " +
                "Collaborator! <br>This extension allows you to work in " +
                "tandem with multiple BurpSuite users by sharing their requests " +
                "with you. Any request that comes through their proxy will " +
                "show up in your site map as well.</html>\n");

        JPanel statusPanel = generatePanel(1, 0);
        statusPanel.setLayout(new BorderLayout(0, 0));
        
        statusText = new JTextPane();
        statusText.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(statusText);
        statusPanel.add(scrollPane);

        JPanel connectionPanel = new JPanel();
        GridBagConstraints gbc_connectionPanel = new GridBagConstraints();
        gbc_connectionPanel.fill = GridBagConstraints.BOTH;
        gbc_connectionPanel.insets = new Insets(0, 0, 5, 5);
        gbc_connectionPanel.gridx = 0;
        gbc_connectionPanel.gridy = 1;
        add(connectionPanel, gbc_connectionPanel);
        connectionPanel.setLayout(new GridLayout(8, 2, 0, 0));
        JLabel yourNameLabel = new JLabel();
        connectionPanel.add(yourNameLabel);
        yourNameLabel.setText("Display Name:");
        this.yourName = new JTextField();
        connectionPanel.add(yourName);
        JLabel theirListenAddress = new JLabel();
        connectionPanel.add(theirListenAddress);
        theirListenAddress.setText("Server Address:");
        this.theirAddress = new JTextField();
        connectionPanel.add(theirAddress);
        JLabel theirListenPort = new JLabel();
        connectionPanel.add(theirListenPort);
        theirListenPort.setText("Server Port:");
        this.theirPort = new JTextField();
        connectionPanel.add(theirPort);
        JLabel serverPasswordLabel = new JLabel();
        serverPasswordLabel.setText("Server Password:");
        connectionPanel.add(serverPasswordLabel);
        this.serverPassword = new JTextField();
        connectionPanel.add(this.serverPassword);
        this.startButton = new JButton();
        connectionPanel.add(startButton);
        this.startButton.setText("Connect");
        this.newRoom = new JButton("New Room");
        this.newRoom.addActionListener(actionEvent1 -> AddRoomButtonActionPerformed());
        this.newRoom.setEnabled(false);
        connectionPanel.add(newRoom);
        this.pauseButton = new JButton();
        this.pauseButton.setEnabled(false);
        connectionPanel.add(pauseButton);
        this.pauseButton.setText("Pause");
        this.pauseButton.addActionListener(actionEvent1 -> PauseButtonActionPerformed());
        this.startButton.addActionListener(actionEvent1 -> StartButtonActionPerformed());
        this.setScopeButton = new JButton("Set Room Scope");
        this.setScopeButton.addActionListener(actionEvent -> setScopeButtonActionPerformed());
        connectionPanel.add(this.setScopeButton);
        this.setScopeButton.setEnabled(false);
        this.leaveRoom = new JButton("Leave Room");
        this.leaveRoom.setEnabled(false);
        this.leaveRoom.addActionListener(actionEvent -> LeaveRoomButtonActionPerformed());
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
            this.sharedValues.getCallbacks().saveExtensionSetting("servername", this.theirAddress.getText());
            this.sharedValues.getCallbacks().saveExtensionSetting("serverport", this.theirPort.getText());
            this.sharedValues.getCallbacks().saveExtensionSetting("serverpass", this.serverPassword.getText());
        });
        connectionPanel.add(this.saveConfigButton);


        JPanel actionPanel = generatePanel(1, 1);
        actionPanel.setLayout(new BorderLayout(2, 2));

        JPopupMenu roomMenu = new JPopupMenu();
        JMenuItem joinRoom = new JMenuItem("Join");
        joinRoom.addActionListener(e1 -> {
            this.sharedValues.getServerConnection().joinRoom(serverList.getSelectedValue());
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
            sharedValues.getServerConnection().muteMember(serverList.getSelectedValue());
        });
        unmuteClient.addActionListener(e1 -> {
            unmuteClient.setEnabled(false);
            muteClient.setEnabled(true);
            sharedValues.getServerConnection().unmuteMember(serverList.getSelectedValue());
        });
        unmuteClient.setEnabled(false);
        clientMenu.add(muteClient);
        clientMenu.add(unmuteClient);
        serverList = new JList<>();
        serverList.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    serverList.setSelectedIndex(serverList.locationToIndex(e.getPoint()));
                    if (!sharedValues.getServerConnection().getYourName()
                            .equals(serverList.getSelectedValue())) {
                        if (sharedValues.getServerConnection().getCurrentRoom().equals("server")) {
                            roomMenu.show(serverList, e.getPoint().x, e.getPoint().y);
                        } else {
                            if (!allMuted) {
                                clientMenu.show(serverList, e.getPoint().x, e.getPoint().y);
                            }
                        }
                    }
                }
            }
        });
        serverList.setModel(this.sharedValues.getServerListModel());
        serverList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        actionPanel.add(serverList);

        JPanel sharedPayloadsPanel = new JPanel(new BorderLayout());
        sharedPayloadsPanel.setBorder(BorderFactory.createLineBorder(Color.white));
        GridBagConstraints gbc_panel = new GridBagConstraints();
        gbc_panel.fill = GridBagConstraints.BOTH;
        gbc_panel.gridx = 0;
        gbc_panel.gridy = 2;
        add(sharedPayloadsPanel, gbc_panel);
        JTable j = new JTable(this.sharedValues.getSharedLinksModel());
        j.setPreferredScrollableViewportSize(j.getPreferredSize());
        final JPopupMenu popupMenu = new JPopupMenu();
        popupMenu.addPopupMenuListener(new PopupMenuListener() {

            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                SwingUtilities.invokeLater(() -> {
                    int rowAtPoint = j.rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), j));
                    System.out.println(rowAtPoint);
                    if (rowAtPoint > -1) {
                        j.setRowSelectionInterval(rowAtPoint, rowAtPoint);

                    }
                });
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
            }
        });
        JMenuItem removeLinkItem = new JMenuItem("Remove Link");
        removeLinkItem.addActionListener(e -> {
            ((SharedLinksModel) j.getModel()).removeBurpMessage(j.getSelectedRow());
        });
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
        sharedPayloadsPanel.add(sp, BorderLayout.CENTER);

    }

    private void muteAllButtonActionPerformed() {
        if (this.allMuted) {
            this.muteAllButton.setText("Mute All");
            sharedValues.getServerConnection().unmuteAllMembers();
        } else {
            this.muteAllButton.setText("Unmute All");
            sharedValues.getServerConnection().muteAllMembers();
        }
        this.allMuted = !this.allMuted;
    }

    private void getScopeButtonActionPerformed() {
        this.sharedValues.getServerConnection().getRoomScope();
    }

    private void setScopeButtonActionPerformed() {
        this.sharedValues.getServerConnection().setRoomScope();
    }

    private void LeaveRoomButtonActionPerformed() {
        this.allMuted = false;
        this.newRoom.setEnabled(true);
        this.muteAllButton.setEnabled(false);
        this.setScopeButton.setEnabled(false);
        this.leaveRoom.setEnabled(false);
        this.pauseButton.setEnabled(false);
        this.getScopeButton.setEnabled(false);
        this.sharedValues.getServerConnection().leaveRoom();
    }

    private void AddRoomButtonActionPerformed() {
        JDialog roomOptions = new JDialog();
        roomOptions.setTitle("Room Options");
        JTextField roomName = new JTextField();
        roomOptions.add(roomName);
        String roomNameValue = JOptionPane.showInputDialog(roomOptions, "Please enter a room name");
        System.out.println(roomNameValue);
        if ((roomNameValue != null) && (roomNameValue.length() > 0)) {
            this.sharedValues.getServerConnection().createRoom(roomNameValue);
            this.muteAllButton.setEnabled(true);
            this.setScopeButton.setEnabled(true);
            this.newRoom.setEnabled(false);
            this.leaveRoom.setEnabled(true);
            this.pauseButton.setEnabled(true);
        }
    }

    private void PauseButtonActionPerformed() {
        if (this.sharedValues.isCommunicating()) {
            this.sharedValues.pauseCommunication();
            this.pauseButton.setText("Unpause");
        } else {
            this.sharedValues.unpauseCommunication();
            this.pauseButton.setText("Pause");
        }
    }

    private String generateHTMLLink(HttpRequestResponse burpMessage) {
        return "<a href='http://burptcmessage/" +
                Base64.getEncoder().encodeToString(this.sharedValues.getGson().toJson(burpMessage).getBytes())
                + "'>" + this.sharedValues.getCallbacks().getHelpers().analyzeRequest(burpMessage).getUrl().toString()
                + "</a>";
    }

    private JPanel generatePanel(int xLocation, int yLocation) {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createLineBorder(Color.white));
        GridBagConstraints gbc_panel = new GridBagConstraints();
        gbc_panel.insets = new Insets(0, 0, 5, 0);
        gbc_panel.fill = GridBagConstraints.BOTH;
        gbc_panel.gridx = xLocation;
        gbc_panel.gridy = yLocation;
        add(panel, gbc_panel);
        return panel;
    }
}
