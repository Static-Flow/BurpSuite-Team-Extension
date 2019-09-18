package teamExtension;

import burp.IExtensionStateListener;

import java.io.IOException;

public class ExtensionStateListener
implements IExtensionStateListener {
    private final SharedValues sharedValues;

    public ExtensionStateListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    public void extensionUnloaded() {
        this.sharedValues.setCustomServerRunning(false);
        try {
            if (this.sharedValues.getInnerServer().getSocket() != null) {
                this.sharedValues.getInnerServer().getSocket().close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (this.sharedValues.isCommunicating()) {
            this.sharedValues.stopCommunication();
        }
    }
}
