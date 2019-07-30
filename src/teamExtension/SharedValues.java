package teamExtension;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import com.google.gson.Gson;

public class SharedValues
implements IProxyListener {
    static final String ROOM = "room";
    private IExtensionHelpers extensionHelpers;
    private ServerConnector serverConnector = null;
    private IBurpExtenderCallbacks callbacks;
    private Gson gson;
    private ServerListModel serverListModel;
    private boolean communicating;
    private AESEncryptDecrypt AESCrypter;
    private String currentScope;


    public SharedValues(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.communicating = false;
        this.extensionHelpers = iBurpExtenderCallbacks.getHelpers();
        this.callbacks = iBurpExtenderCallbacks;
        this.gson = new Gson();
        this.serverListModel = new ServerListModel();
        this.currentScope = getCallbacks().saveConfigAsJson("target.scope");
    }

    AESEncryptDecrypt getAESCrypter() {
        return this.AESCrypter;
    }

    void initAESCrypterWithKey(String key) {
        this.AESCrypter = new AESEncryptDecrypt(key);
    }

    ServerListModel getServerListModel() {
        return serverListModel;
    }

    void startCommunication() {
        this.callbacks.registerProxyListener(this);
        this.communicating = true;
    }

    void stopCommunication() {
        this.serverConnector.leave();
        this.communicating = false;
        this.serverListModel.removeAllElements();
        this.callbacks.removeProxyListener(this);
    }

    ServerConnector getServerConnection() {
        return this.serverConnector;
    }

    void setServerConnection(ServerConnector serverConnector) {
        this.serverConnector = serverConnector;
    }

    void doneListening() {
        this.serverConnector.cutTheHardLine();
        this.communicating = false;
        this.serverListModel.removeAllElements();
        this.callbacks.removeProxyListener(this);
    }

    Gson getGson() {
        return this.gson;
    }

    IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    public void processProxyMessage(boolean isResponse,
                                    IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!isResponse && this.communicating) {
	        HttpRequestResponse httpRequestResponse = new HttpRequestResponse(iInterceptedProxyMessage.getMessageInfo());
            BurpTCMessage burpMessage = new BurpTCMessage(httpRequestResponse, MessageType.BURP_MESSAGE,
                    this.getServerConnection().getCurrentRoom(), ROOM, null);
            this.getServerConnection().sendMessage(burpMessage);
        }
    }

    IExtensionHelpers getExtensionHelpers() {
        return extensionHelpers;
    }

    boolean isCommunicating() {
        return this.communicating;
    }

    void pauseCommunication() {
        this.communicating = false;
    }

    void unpauseCommunication() {
        this.communicating = true;
    }

    String getCurrentScope() {
        return this.currentScope;
    }

    void setCurrentScope(String scopeJson) {

        this.currentScope = scopeJson;
        System.out.println(this.currentScope);
    }
}
