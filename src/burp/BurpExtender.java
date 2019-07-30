package burp;

import teamExtension.*;

import java.awt.*;

public class BurpExtender
implements IBurpExtender,
        ITab {
    private SharedValues sharedValues;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        iBurpExtenderCallbacks.setExtensionName("Burp Team Collaborator");
        this.sharedValues = new SharedValues(iBurpExtenderCallbacks);
        iBurpExtenderCallbacks.registerScopeChangeListener(new ScopeChangeListener(this.sharedValues));
        iBurpExtenderCallbacks.registerExtensionStateListener(new ExtensionStateListener(this.sharedValues));
        iBurpExtenderCallbacks.registerContextMenuFactory(new ManualRequestSenderContextMenu(this.sharedValues));
        iBurpExtenderCallbacks.addSuiteTab(this);
    }

    public String getTabCaption() {
        return "Burp TC";
    }

    public Component getUiComponent() {
        return new BurpTeamPanel(this.sharedValues);
    }
}
