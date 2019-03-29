/*
 * Decompiled with CFR 0.139.
 * 
 * Could not load the following classes:
 *  burp.IBurpExtender
 *  burp.IBurpExtenderCallbacks
 *  burp.IExtensionStateListener
 *  burp.ITab
 *  burp.StartBurp
 */
package burp;

import burp.BurpTeamPanel;
import burp.ExtentionStateListener;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;
import burp.SharedValues;
import burp.StartBurp;
import java.awt.Component;

public class BurpExtender
implements IBurpExtender,
ITab {
    private IBurpExtenderCallbacks callbacks;
    private SharedValues sharedValues;

    public static void main(String[] arrstring) {
        StartBurp.main((String[])arrstring);
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        iBurpExtenderCallbacks.setExtensionName("Burp Team Collaborator");
        this.sharedValues = new SharedValues(this.callbacks);
        iBurpExtenderCallbacks.registerExtensionStateListener((IExtensionStateListener)new ExtentionStateListener(this.sharedValues));
        this.callbacks.addSuiteTab((ITab)this);
    }

    public String getTabCaption() {
        return "Burp TC";
    }

    public Component getUiComponent() {
        return new BurpTeamPanel(this.sharedValues);
    }
}
