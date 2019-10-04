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
        HttpRequestResponse req = new HttpRequestResponse();
        req.setRequest(new byte[]{1, 2, 3});
        req.setResponse(new byte[]{1, 2, 3});
        req.setHttpService(new HttpService());
        new CommentFrame(callbacks, req, "me");
//        sharedValues = new SharedValues(iBurpExtenderCallbacks);
//        CustomURLServer innerServer;
//        try {
//            innerServer = new CustomURLServer(sharedValues);
//            Thread innerServerThread = new Thread(innerServer);
//            innerServerThread.start();
//            sharedValues.setInnerServer(innerServer);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//        iBurpExtenderCallbacks.registerProxyListener(sharedValues);
//        iBurpExtenderCallbacks.registerScopeChangeListener(new ScopeChangeListener(this.sharedValues));
//        iBurpExtenderCallbacks.registerExtensionStateListener(new ExtensionStateListener(this.sharedValues));
//        iBurpExtenderCallbacks.registerContextMenuFactory(new ManualRequestSenderContextMenu(this.sharedValues));
//        iBurpExtenderCallbacks.registerScannerListener(new ScannerListener(this.sharedValues));
//        iBurpExtenderCallbacks.addSuiteTab(this);
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
