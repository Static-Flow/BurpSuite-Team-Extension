package teamextension;

import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import javax.net.ssl.*;
import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class SharedValues {
    static final String ROOM = "Room";
    static final String EXTENSION_NAME = "Burp TC";
    static final Type cookieJsonListType = new TypeToken<List<Cookie>>() {
    }.getType();
    boolean innerServerRunning;
    private BurpClient chatClient;
    private final IBurpExtenderCallbacks callbacks;
    private final Gson gson;
    private final ServerListModel serverListModel;
    private final RoomMembersListModel roomMembersListModel;
    private final SharedLinksModel sharedLinksModel;
    private String currentScope;
    private CustomURLServer innerServer;
    private final List<ICookie> currentCookieJar;
    private BurpTeamPanel burpPanel;
    private File certFile;
    private File certKeyFile;
    private RequestCommentModel requestCommentModel;
    private String serverUrlShortenerApiKey;


    public SharedValues(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.currentCookieJar = this.callbacks.getCookieJarContents();
        GsonBuilder builder = new GsonBuilder();
        builder.registerTypeAdapter(Date.class, new DateDeserializer(callbacks));
        builder.registerTypeAdapter(RequestComment.class,
                new RequestCommentSerializer());
        this.gson =
                builder.setDateFormat("MMM dd HH:mm:ss").create();
        this.serverListModel = new ServerListModel();
        this.roomMembersListModel = new RoomMembersListModel();
        this.sharedLinksModel = new SharedLinksModel(this);
        this.requestCommentModel = new RequestCommentModel(this);
        this.currentScope = getCallbacks().saveConfigAsJson("target.scope");
    }

    RoomMembersListModel getRoomMembersListModel() {
        return this.roomMembersListModel;
    }

    ServerListModel getServerListModel() {
        return serverListModel;
    }

    boolean connectToServer(String serverUrl, String serverPassword,
                            String username) {
        try {
            this.chatClient = new BurpClient(serverUrl, serverPassword,
                    username, this);
            return true;
        } catch (URISyntaxException e) {
            this.callbacks.printError(e.getMessage());
            serverConnectionFailure(-2);
            return false;
        } catch (NullPointerException e) {
            getCallbacks().printError("User forgot to set " +
                    "cert/key files");
            serverConnectionFailure(-3);
            return false;
        }
    }

    void closeCommentSessions() {
        this.requestCommentModel.clearValues();
        for (CommentFrame commentSession : getRequestCommentModel().getCommentSessions()) {
            commentSession.close();
        }
    }

    BurpClient getClient() {
        return this.chatClient;
    }

    void serverConnectionFailure(int reason) {
        this.burpPanel.resetConnectionUIWithReason(reason);
    }

    Gson getGson() {
        return this.gson;
    }

    IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    void shareNewCookies() {
        if (this.getBurpPanel().getShareCookiesSetting()) {
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    List<Cookie> newItems = new ArrayList<>();
                    for (ICookie cookie : callbacks.getCookieJarContents()) {
                        if (currentCookieJar.contains(cookie)) {
                            if (!currentCookieJar.get(currentCookieJar.indexOf(cookie)).equals(cookie)) {
                                newItems.add(new Cookie(cookie));
                            }
                        } else {
                            newItems.add(new Cookie(cookie));
                        }
                    }
                    BurpTCMessage cookieMessage = new BurpTCMessage(null, MessageType.COOKIE_MESSAGE, getGson().toJson(newItems, cookieJsonListType));
                    getClient().sendMessage(cookieMessage);
                    return Boolean.TRUE;
                }

                @Override
                public void done() {
                    //we don't need to do any cleanup so this is empty
                }
            }.execute();
        }
    }

    String getCurrentScope() {
        return this.currentScope;
    }

    void setCurrentScope(String scopeJson) {

        this.currentScope = scopeJson;
        this.callbacks.printOutput(this.currentScope);
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
        try {
            getCallbacks().excludeFromScope(new URL("http://burptcmessage"));
        } catch (MalformedURLException e) {
            this.callbacks.printError(e.getMessage());
        }
    }

    BurpTeamPanel getBurpPanel() {
        return this.burpPanel;
    }

    public void setBurpPanel(BurpTeamPanel panel) {
        this.burpPanel = panel;
    }

    RequestCommentModel getRequestCommentModel() {
        return requestCommentModel;
    }


    void setCertFile(File certFile) {
        this.certFile = certFile;
    }

    void setCertKeyFile(File certKeyFile) {
        this.certKeyFile = certKeyFile;
    }

    File getCertFile() {
        return certFile;
    }

    File getCertKeyFile() {
        return certKeyFile;
    }

    void setUrlShortenerApiKey(String shortenerApiKey) {
        this.serverUrlShortenerApiKey = shortenerApiKey;
    }

    String getUrlShortenerApiKey() {
        return this.serverUrlShortenerApiKey;
    }

    HttpsURLConnection getUnsafeURL(URL url) throws NoSuchAlgorithmException, KeyManagementException, IOException {
        TrustManager[] trustAllCerts =
                new TrustManager[]{new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
                };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = (hostname, session) -> true;

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        return (HttpsURLConnection) url.openConnection();
    }

}
