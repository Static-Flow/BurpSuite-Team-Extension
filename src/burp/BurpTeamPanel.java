/*
 * Decompiled with CFR 0.139.
 * 
 * Could not load the following classes:
 *  burp.ServerConnector
 */
package burp;

import burp.ServerConnector;
import burp.SharedValues;
import java.awt.Component;
import java.awt.Container;
import java.awt.LayoutManager;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.LayoutStyle;

public class BurpTeamPanel
extends JPanel {
    private SharedValues sharedValues;
    private JLabel Explainer;
    private JButton StartButton;
    private JButton StopButton;
    private JLabel yourNameLabel;
    private JTextField yourName;
    private JLabel theirListenPort;
    private JTextField theirPort;
    private JLabel TheirListenAddress;
    private JTextField theirAddress;

    public BurpTeamPanel(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
        this.initComponents();
    }

    private void StartButtonActionPerformed(ActionEvent actionEvent) {
        this.sharedValues.setServerConnection(new ServerConnector(this.theirAddress.getText(), Integer.parseInt(this.theirPort.getText()), this.yourName.getText(), this.sharedValues.getStderr(), this.sharedValues));
        this.sharedValues.startCommunication();
    }

    private void StopButtonActionPerformed(ActionEvent actionEvent) {
        this.sharedValues.stopCommunication();
    }

    private void initComponents() {
        this.Explainer = new JLabel();
        this.StartButton = new JButton();
        this.StopButton = new JButton();
        this.yourNameLabel = new JLabel();
        this.yourName = new JTextField();
        this.theirListenPort = new JLabel();
        this.theirPort = new JTextField();
        this.TheirListenAddress = new JLabel();
        this.theirAddress = new JTextField();
        this.Explainer.setText("Welcome to the BurpSuite Team Server! This extension allows you to work in tandem with another BurpSuite user by sharing their requests with you. Any request that comes through their proxy will show up in your site map as well.\n");
        this.StartButton.setText("Start");
        this.StartButton.addActionListener(actionEvent -> this.StartButtonActionPerformed(actionEvent));
        this.StopButton.setText("Stop");
        this.StopButton.addActionListener(actionEvent -> this.StopButtonActionPerformed(actionEvent));
        this.yourNameLabel.setText("Your Name:");
        this.theirListenPort.setText("Their Port:");
        this.TheirListenAddress.setText("Their IP Address:");
        GroupLayout groupLayout = new GroupLayout(this);
        this.setLayout(groupLayout);
        groupLayout.setHorizontalGroup(groupLayout.createParallelGroup().addGroup(groupLayout.createSequentialGroup().addContainerGap().addGroup(groupLayout.createParallelGroup().addComponent(this.Explainer, -2, 378, -2).addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.TRAILING, false).addGroup(GroupLayout.Alignment.LEADING, groupLayout.createSequentialGroup().addComponent(this.TheirListenAddress).addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(this.theirAddress, -1, 90, 32767)).addGroup(GroupLayout.Alignment.LEADING, groupLayout.createSequentialGroup().addGroup(groupLayout.createParallelGroup().addComponent(this.yourNameLabel).addComponent(this.theirListenPort)).addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false).addComponent(this.theirPort, -1, 90, 32767).addComponent(this.yourName, -1, 90, 32767)))).addGroup(groupLayout.createSequentialGroup().addComponent(this.StartButton).addPreferredGap(LayoutStyle.ComponentPlacement.RELATED).addComponent(this.StopButton))).addContainerGap(16, 32767)));
        groupLayout.setVerticalGroup(groupLayout.createParallelGroup().addGroup(groupLayout.createSequentialGroup().addContainerGap().addComponent(this.Explainer, -2, 52, -2).addPreferredGap(LayoutStyle.ComponentPlacement.RELATED).addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(this.yourNameLabel).addComponent(this.yourName, -2, -1, -2)).addGap(6, 6, 6).addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(this.theirListenPort).addComponent(this.theirPort, -2, -1, -2)).addGap(6, 6, 6).addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(this.TheirListenAddress).addComponent(this.theirAddress, -2, -1, -2)).addPreferredGap(LayoutStyle.ComponentPlacement.RELATED).addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(this.StartButton).addComponent(this.StopButton)).addContainerGap(114, 32767)));
    }
}
