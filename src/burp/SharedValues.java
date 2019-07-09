package burp;

import com.google.gson.Gson;

import java.io.PrintWriter;
import java.net.URL;

public class SharedValues
implements IProxyListener {
    private IExtensionHelpers extentionHelpers;
    private URL teammateServerUrl = null;
    private int teammateServerPort = 0;
    private int yourPort;
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
        this.serverListModel.setServerConnected(true);
        this.getServerConnection().sendMessage(
                "newroommates");
    }

    public void stopCommunication() {
        this.serverConnector.leave();
        this.communicating = false;
        this.serverListModel.setServerConnected(false);
        this.callbacks.removeProxyListener(this);
    }

    public ServerConnector getServerConnection() {
        return this.serverConnector;
    }

    public void setServerConnection(ServerConnector serverConnector) {
        this.serverConnector = serverConnector;
    }

    public int getYourPort() {
        return this.yourPort;
    }

    public void setYourPort(int n) {
        this.yourPort = n;
    }

    public PrintWriter getStdout() {
        return this.stdout;
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

    public URL getTeammateServerUrl() {
        return this.teammateServerUrl;
    }

    public void setTeammateServerUrl(URL uRL) {
        this.teammateServerUrl = uRL;
    }

    public int getTeammateServerPort() {
        return this.teammateServerPort;
    }

    public void setTeammateServerPort(int n) {
        this.teammateServerPort = n;
    }

    public void processProxyMessage(boolean isResponse,
                                    IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!isResponse && this.communicating) {
	        HttpRequestResponse httpRequestResponse = new HttpRequestResponse(iInterceptedProxyMessage.getMessageInfo());
	        this.getServerConnection().sendMessage(this.gson.toJson(httpRequestResponse));
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
