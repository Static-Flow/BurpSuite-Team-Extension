package teamExtension;

import burp.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

public class SharedValues
implements IProxyListener {
    static final String ROOM = "room";
    static final Type cookieJsonListType = new TypeToken<List<Cookie>>() {
    }.getType();
    boolean innerServerRunning;
    private final IExtensionHelpers extensionHelpers;
    private ServerConnector serverConnector = null;
    private final IBurpExtenderCallbacks callbacks;
    private final Gson gson;
    private final ServerListModel serverListModel;
    private final SharedLinksModel sharedLinksModel;
    private boolean communicating;
    private AESEncryptDecrypt AESCrypter;
    private String currentScope;
    private CustomURLServer innerServer;
    private final List<ICookie> currentCookieJar;


    public SharedValues(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.communicating = false;
        this.callbacks = iBurpExtenderCallbacks;
        this.extensionHelpers = this.callbacks.getHelpers();
        this.currentCookieJar = this.callbacks.getCookieJarContents();
        GsonBuilder builder = new GsonBuilder();
        this.gson = builder.create();
        this.serverListModel = new ServerListModel();
        this.sharedLinksModel = new SharedLinksModel(this);
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
        if (!this.getServerConnection().getCurrentRoom().equals(this.getServerConnection().SERVER)) {
            this.serverConnector.leaveRoom();
        }
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
        IHttpService httpService = iInterceptedProxyMessage.getMessageInfo().getHttpService();
        if ("burptcmessage".equalsIgnoreCase(iInterceptedProxyMessage.getMessageInfo().getHttpService().getHost())) {
            System.out.println("got custom link request");
            iInterceptedProxyMessage.getMessageInfo().setHttpService(this.getCallbacks().getHelpers().buildHttpService(
                    "127.0.0.1", 8888, httpService.getProtocol()));
            httpService = iInterceptedProxyMessage.getMessageInfo().getHttpService();
            System.out.println(httpService.getHost());
        } else if (!isResponse && this.communicating) {
            HttpRequestResponse httpRequestResponse = new HttpRequestResponse(iInterceptedProxyMessage.getMessageInfo());
            BurpTCMessage burpMessage = new BurpTCMessage(httpRequestResponse, MessageType.BURP_MESSAGE,
                    this.getServerConnection().getCurrentRoom(), ROOM, null);
            this.getServerConnection().sendMessage(burpMessage);
            shareNewCookies();

        }
    }

    private void shareNewCookies() {
        List<Cookie> newItems = new ArrayList<>();
        for (ICookie cookie : this.callbacks.getCookieJarContents()) {
            if (this.currentCookieJar.contains(cookie)) {
                if (!this.currentCookieJar.get(this.currentCookieJar.indexOf(cookie)).equals(cookie)) {
                    newItems.add(new Cookie(cookie));
                }
            } else {
                newItems.add(new Cookie(cookie));
            }
        }
        BurpTCMessage cookieMessage = new BurpTCMessage(null, MessageType.COOKIE_MESSAGE,
                this.getServerConnection().getCurrentRoom(), ROOM, this.getGson().toJson(newItems, cookieJsonListType));
        this.getServerConnection().sendMessage(cookieMessage);
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

    SharedLinksModel getSharedLinksModel() {
        return sharedLinksModel;
    }

    void setCustomServerRunning(boolean running) {
        this.innerServerRunning = running;
    }

    CustomURLServer getInnerServer() {
        return this.innerServer;
    }

    public void setInnerServer(CustomURLServer innerServer) {
        this.innerServer = innerServer;
        this.setCustomServerRunning(true);
    }
}
