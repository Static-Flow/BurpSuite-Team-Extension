package burp;

import teamextension.*;

import java.awt.*;
import java.io.IOException;

public class BurpExtender
        implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private SharedValues sharedValues;
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        callbacks.setExtensionName("Burp Suite Team Collaborator");
        sharedValues = new SharedValues(iBurpExtenderCallbacks);
        CustomURLServer innerServer;
        try {
            innerServer = new CustomURLServer(sharedValues);
            Thread innerServerThread = new Thread(innerServer);
            innerServerThread.start();
            sharedValues.setInnerServer(innerServer);
        } catch (IOException e) {
            callbacks.printError(e.getMessage());
        }

        iBurpExtenderCallbacks.registerProxyListener(new ProxyListener(this.sharedValues));
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
        this.sharedValues.setBurpPanel(panel);
        callbacks.customizeUiComponent(panel);
        return panel;
    }
}
