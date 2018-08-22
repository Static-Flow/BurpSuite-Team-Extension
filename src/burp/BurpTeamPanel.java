/*
 * Created by JFormDesigner on Mon Aug 20 23:09:05 CDT 2018
 */

package burp;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
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
            URL theirUrl = new URL("http://"+theirAddress.getText()+"/message");
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

    private void replayReqChkBoxStateChanged(ChangeEvent e) {
        //Just toggle the setting for replaying requests
        this.sharedValues.setReplayRequests(!this.sharedValues
                .getReplayRequests());
    }

    private void shareRepeaterReqChkBoxStateChanged(ChangeEvent e) {
        JCheckBox startStopMonitoringBurpTools = (JCheckBox) e.getSource();
        if(startStopMonitoringBurpTools.isSelected()){
            this.sharedValues.startMonitoringBurpTools();
        }else{
            this.sharedValues.stopMonitoringBurpTools();
        }
    }

    private void verboseDebuggingChkStateChanged(ChangeEvent e) {
        this.sharedValues.setVerboseDebug(!this.sharedValues.getVerboseDebug());
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
        replayReqChkBox = new JCheckBox();
        shareRepeaterReqChkBox = new JCheckBox();
        verboseDebuggingChk = new JCheckBox();

        //======== this ========

        // JFormDesigner evaluation mark
        setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.TitledBorder(new javax.swing.border.EmptyBorder(0, 0, 0, 0),
                "JFormDesigner Evaluation", javax.swing.border.TitledBorder.CENTER,
                javax.swing.border.TitledBorder.BOTTOM, new java.awt.Font("Dialog", java.awt.Font.BOLD, 12),
                java.awt.Color.red), getBorder())); addPropertyChangeListener(new java.beans.PropertyChangeListener(){public void propertyChange(java.beans.PropertyChangeEvent e){if("border".equals(e.getPropertyName()))throw new RuntimeException();}});


        //---- Explainer ----
        Explainer.setText("Welcome to the BurpSuite Team Server! ");

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

        //---- replayReqChkBox ----
        replayReqChkBox.setText("Replay Received Requests");
        replayReqChkBox.setHorizontalTextPosition(SwingConstants.LEADING);
        replayReqChkBox.addChangeListener(e -> replayReqChkBoxStateChanged(e));

        //---- shareRepeaterReqChkBox ----
        shareRepeaterReqChkBox.setText("Share Burp Tool Requests");
        shareRepeaterReqChkBox.setHorizontalTextPosition(SwingConstants.LEADING);
        shareRepeaterReqChkBox.setIconTextGap(5);
        shareRepeaterReqChkBox.addChangeListener(e -> shareRepeaterReqChkBoxStateChanged(e));

        //---- verboseDebuggingChk ----
        verboseDebuggingChk.setText("Verbose Debug Mode On");
        verboseDebuggingChk.setHorizontalTextPosition(SwingConstants.LEADING);
        verboseDebuggingChk.setIconTextGap(6);
        verboseDebuggingChk.addChangeListener(e -> verboseDebuggingChkStateChanged(e));

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup()
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(StartButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(StopButton)
                            .addGap(0, 0, Short.MAX_VALUE))
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup()
                                .addComponent(Explainer, GroupLayout.DEFAULT_SIZE, 0, Short.MAX_VALUE)
                                .addGroup(layout.createSequentialGroup()
                                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addGroup(GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                            .addComponent(TheirListenAddress)
                                            .addGap(18, 18, 18)
                                            .addComponent(theirAddress, GroupLayout.PREFERRED_SIZE, 96, GroupLayout.PREFERRED_SIZE)
                                            .addGap(0, 0, Short.MAX_VALUE))
                                        .addGroup(layout.createSequentialGroup()
                                            .addGroup(layout.createParallelGroup()
                                                .addComponent(yourListenPort)
                                                .addComponent(theirListenPort))
                                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addGroup(layout.createParallelGroup()
                                                .addComponent(yourPort, GroupLayout.PREFERRED_SIZE, 96, GroupLayout.PREFERRED_SIZE)
                                                .addComponent(theirPort, GroupLayout.PREFERRED_SIZE, 96, GroupLayout.PREFERRED_SIZE))))
                                    .addGroup(layout.createParallelGroup()
                                        .addGroup(layout.createSequentialGroup()
                                            .addGap(17, 17, 17)
                                            .addGroup(layout.createParallelGroup()
                                                .addComponent(replayReqChkBox, GroupLayout.DEFAULT_SIZE, 169, Short.MAX_VALUE)
                                                .addComponent(shareRepeaterReqChkBox, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                                        .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, 17, Short.MAX_VALUE)
                                            .addComponent(verboseDebuggingChk, GroupLayout.PREFERRED_SIZE, 169, GroupLayout.PREFERRED_SIZE)))))
                            .addContainerGap())))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(Explainer, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(yourListenPort)
                        .addComponent(replayReqChkBox)
                        .addComponent(yourPort, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addGap(10, 10, 10)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(theirListenPort)
                        .addComponent(shareRepeaterReqChkBox)
                        .addComponent(theirPort, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(TheirListenAddress)
                        .addComponent(theirAddress, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(verboseDebuggingChk))
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(StartButton)
                        .addComponent(StopButton))
                    .addContainerGap(104, Short.MAX_VALUE))
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
    private JCheckBox replayReqChkBox;
    private JCheckBox shareRepeaterReqChkBox;
    private JCheckBox verboseDebuggingChk;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}
