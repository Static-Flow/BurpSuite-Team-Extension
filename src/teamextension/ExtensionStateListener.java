package teamextension;

import burp.IExtensionStateListener;

import java.io.IOException;

public class ExtensionStateListener
implements IExtensionStateListener {
    private final SharedValues sharedValues;

    public ExtensionStateListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    public void extensionUnloaded() {
        this.sharedValues.closeCommentSessions();
        this.sharedValues.setCustomServerRunning(false);
        try {
            if (this.sharedValues.getInnerServer().getSocket() != null) {
                this.sharedValues.getInnerServer().getSocket().close();
            }
        } catch (IOException e) {
            this.sharedValues.getCallbacks().printError(e.getMessage());
        }
        if (this.sharedValues.getClient() != null && this.sharedValues.getClient().isConnected()) {
            if (this.sharedValues.getBurpPanel().inRoom()) {
                this.sharedValues.getClient().leaveRoom();
            }
            this.sharedValues.getClient().leaveServer();
        }
    }
}
