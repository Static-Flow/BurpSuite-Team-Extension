package burp;

import com.google.gson.Gson;

import java.io.PrintWriter;

public class SharedValues
implements IProxyListener {
    private IExtensionHelpers extentionHelpers;
    private ServerConnector serverConnector = null;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private Gson gson;
    private ServerListModel serverListModel;
    private boolean communicating;


    public SharedValues(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        if (this.stdout == null && this.stderr == null) {
            this.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
            this.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        }
        this.communicating = false;
        this.extentionHelpers = iBurpExtenderCallbacks.getHelpers();
        this.callbacks = iBurpExtenderCallbacks;
        this.gson = new Gson();
        this.serverListModel = new ServerListModel();
    }

    public ServerListModel getServerListModel() {
        return serverListModel;
    }

    public void startCommunication() {
        this.callbacks.registerProxyListener(this);
        this.communicating = true;
    }

    public void stopCommunication() {
        this.serverConnector.leave();
        this.communicating = false;
        this.serverListModel.removeAllElements();
        this.callbacks.removeProxyListener(this);
    }

    public ServerConnector getServerConnection() {
        return this.serverConnector;
    }

    public void setServerConnection(ServerConnector serverConnector) {
        this.serverConnector = serverConnector;
    }

    public PrintWriter getStderr() {
        return this.stderr;
    }

    public Gson getGson() {
        return this.gson;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    public void processProxyMessage(boolean isResponse,
                                    IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!isResponse && this.communicating) {
	        HttpRequestResponse httpRequestResponse = new HttpRequestResponse(iInterceptedProxyMessage.getMessageInfo());
            BurpTCMessage burpMessage = new BurpTCMessage(httpRequestResponse, MessageType.BURP_MESSAGE,
                    "dev", "room", null);
            this.getServerConnection().sendMessage(burpMessage);
        }
    }

    public IExtensionHelpers getExtentionHelpers() {
        return extentionHelpers;
    }

    public boolean isCommunicating() {
        return this.communicating;
    }

    public void pauseCommunication() {
        this.communicating = false;
    }

    public void unpauseCommunication() {
        this.communicating = true;
    }

}
