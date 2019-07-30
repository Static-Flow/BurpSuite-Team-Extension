package teamExtension;

import burp.IExtensionStateListener;

public class ExtensionStateListener
implements IExtensionStateListener {
    private SharedValues sharedValues;

    public ExtensionStateListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    public void extensionUnloaded() {
        if (this.sharedValues.isCommunicating()) {
            this.sharedValues.stopCommunication();
        }
    }
}
