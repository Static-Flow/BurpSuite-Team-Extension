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
import burp.SharedValues;

import java.awt.Component;

public class BurpExtender
implements IBurpExtender,
ITab {
    private IBurpExtenderCallbacks callbacks;
    private SharedValues sharedValues;

    public static void main(String[] arrstring) {

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
