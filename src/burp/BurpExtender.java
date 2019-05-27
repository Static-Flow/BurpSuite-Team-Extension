package burp;

import java.awt.*;

public class BurpExtender
implements IBurpExtender,
        ITab {
    private IBurpExtenderCallbacks callbacks;
    private SharedValues sharedValues;

    public static void main(String[] arrstring) {

    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.callbacks.setExtensionName("Burp Team Collaborator");
        this.sharedValues = new SharedValues(this.callbacks);
        this.callbacks.registerExtensionStateListener(new ExtentionStateListener(this.sharedValues));
        this.callbacks.registerContextMenuFactory(new ManualRequestSenderContextMenu(this.sharedValues));
        this.callbacks.addSuiteTab(this);
    }

    public String getTabCaption() {
        return "Burp TC";
    }

    public Component getUiComponent() {
        return new BurpTeamPanel(this.sharedValues);
    }
}
