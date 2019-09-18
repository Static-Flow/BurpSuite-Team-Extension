package burp;

import teamExtension.*;

import java.awt.*;

public class BurpExtender
implements IBurpExtender,
        ITab {
    private SharedValues sharedValues;
    private IBurpExtenderCallbacks callbacks;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        iBurpExtenderCallbacks.setExtensionName("Burp Team Collaborator");
        sharedValues = new SharedValues(iBurpExtenderCallbacks);
        CustomURLServer innerServer = new CustomURLServer(sharedValues);
        Thread innerServerThread = new Thread(innerServer);
        innerServerThread.start();
        sharedValues.setInnerServer(innerServer);
        iBurpExtenderCallbacks.registerProxyListener(sharedValues);
        iBurpExtenderCallbacks.registerScopeChangeListener(new ScopeChangeListener(this.sharedValues));
        iBurpExtenderCallbacks.registerExtensionStateListener(new ExtensionStateListener(this.sharedValues));
        iBurpExtenderCallbacks.registerContextMenuFactory(new ManualRequestSenderContextMenu(this.sharedValues));
        iBurpExtenderCallbacks.registerScannerListener(new ScannerListener(this.sharedValues));
        iBurpExtenderCallbacks.addSuiteTab(this);
    }

    public String getTabCaption() {
        return "Burp TC";
    }

    public Component getUiComponent() {
        BurpTeamPanel panel = new BurpTeamPanel(this.sharedValues);
        callbacks.customizeUiComponent(panel);
        return panel;
    }
}
