/*
 * Created by JFormDesigner on Mon Aug 20 23:09:05 CDT 2018
 */

package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;

public class BurpTeamPanel extends JPanel {
    private SharedValues sharedValues;

    public BurpTeamPanel(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
        initComponents();
    }

    private void StartButtonActionPerformed(ActionEvent ev) {
        this.sharedValues.setTeammateServerPort(Integer.parseInt(theirPort
                .getText()));
        try {
            URL theirUrl = new URL(theirAddress.getText()+"/message");
            theirUrl = new URL(theirUrl.getProtocol(),theirUrl.getHost(),this
                    .sharedValues.getTeammateServerPort(),theirUrl.getFile());
            this.sharedValues.setTeammateServerUrl(theirUrl);
        } catch (MalformedURLException e) {
            this.sharedValues.getStderr().println(e.getMessage());
        }
        this.sharedValues.setYourPort(Integer.parseInt(yourPort.getText()));
        this.sharedValues.startCommunication();
    }

    private void StopButtonActionPerformed(ActionEvent e) {
        this.sharedValues.stopCommunication();
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        // Generated using JFormDesigner Evaluation license - tanner barnes
        Explainer = new JLabel();
        StartButton = new JButton();
        StopButton = new JButton();
        yourListenPort = new JLabel();
        yourPort = new JTextField();
        theirListenPort = new JLabel();
        theirPort = new JTextField();
        TheirListenAddress = new JLabel();
        theirAddress = new JTextField();

        //======== this ========

        // JFormDesigner evaluation mark
        setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.TitledBorder(new javax.swing.border.EmptyBorder(0, 0, 0, 0),
                "JFormDesigner Evaluation", javax.swing.border.TitledBorder.CENTER,
                javax.swing.border.TitledBorder.BOTTOM, new java.awt.Font("Dialog", java.awt.Font.BOLD, 12),
                java.awt.Color.red), getBorder())); addPropertyChangeListener(new java.beans.PropertyChangeListener(){public void propertyChange(java.beans.PropertyChangeEvent e){if("border".equals(e.getPropertyName()))throw new RuntimeException();}});


        //---- Explainer ----
        Explainer.setText("Welcome to the BurpSuite Team Server! This extension allows you to work in tandem with another BurpSuite user by sharing their requests with you. Any request that comes through their proxy will show up in your site map as well.\n");

        //---- StartButton ----
        StartButton.setText("Start");
        StartButton.addActionListener(e -> StartButtonActionPerformed(e));

        //---- StopButton ----
        StopButton.setText("Stop");
        StopButton.addActionListener(e -> StopButtonActionPerformed(e));

        //---- yourListenPort ----
        yourListenPort.setText("Your Server Port:");

        //---- theirListenPort ----
        theirListenPort.setText("Their Port:");

        //---- TheirListenAddress ----
        TheirListenAddress.setText("Their IP Address:");

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup()
                        .addComponent(Explainer, GroupLayout.PREFERRED_SIZE, 378, GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING, false)
                            .addGroup(GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                .addComponent(TheirListenAddress)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(theirAddress, GroupLayout.DEFAULT_SIZE, 90, Short.MAX_VALUE))
                            .addGroup(GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup()
                                    .addComponent(yourListenPort)
                                    .addComponent(theirListenPort))
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                    .addComponent(theirPort, GroupLayout.DEFAULT_SIZE, 90, Short.MAX_VALUE)
                                    .addComponent(yourPort, GroupLayout.DEFAULT_SIZE, 90, Short.MAX_VALUE))))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(StartButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(StopButton)))
                    .addContainerGap(16, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(Explainer, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(yourListenPort)
                        .addComponent(yourPort, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addGap(6, 6, 6)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(theirListenPort)
                        .addComponent(theirPort, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addGap(6, 6, 6)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(TheirListenAddress)
                        .addComponent(theirAddress, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(StartButton)
                        .addComponent(StopButton))
                    .addContainerGap(114, Short.MAX_VALUE))
        );
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    // Generated using JFormDesigner Evaluation license - tanner barnes
    private JLabel Explainer;
    private JButton StartButton;
    private JButton StopButton;
    private JLabel yourListenPort;
    private JTextField yourPort;
    private JLabel theirListenPort;
    private JTextField theirPort;
    private JLabel TheirListenAddress;
    private JTextField theirAddress;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}
