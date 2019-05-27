/*
 * Decompiled with CFR 0.139.
 * 
 * Could not load the following classes:
 *  burp.IExtensionStateListener
 *  burp.ServerConnector
 */
package burp;

public class ExtentionStateListener
implements IExtensionStateListener {
    private SharedValues sharedValues;

    public ExtentionStateListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    public void extensionUnloaded() {
        this.sharedValues.getServerConnection().stop();
    }
}
