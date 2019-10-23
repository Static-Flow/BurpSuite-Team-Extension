package teamextension;

import burp.ICookie;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.handshake.ServerHandshake;

import javax.net.ssl.*;
import javax.swing.*;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Type;
import java.net.ConnectException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

class BurpClient {

    private static final String SERVER = "server";
    private final String username;
    private WebSocketClient cc;
    private SharedValues sharedValues;
    private ArrayList<String> mutedClients;
    private String currentRoom = SERVER;
    private boolean paused;

    BurpClient(String serverAddress,
               final String serverPassword,
               final String username,
               SharedValues sharedValues) throws URISyntaxException {
        this.username = username;
        mutedClients = new ArrayList<>();
        this.paused = false;
        this.sharedValues = sharedValues;
        HashMap<String, String> authHeaders = new HashMap<>();
        authHeaders.put("Auth", serverPassword);
        authHeaders.put("Username", username);
        cc = new WebSocketClient(new URI("wss://" + serverAddress),
                authHeaders) {

            @Override
            public void onMessage(String message) {
                new SwingWorker<Boolean, Void>() {
                    @Override
                    public Boolean doInBackground() {
                        try {
                            BurpTCMessage burpTCMessage =
                                    sharedValues.getGson().fromJson(new String(sharedValues.getCallbacks().getHelpers().base64Decode(message)),
                                            BurpTCMessage.class);
                            parseBurpTCMessage(burpTCMessage);
                        } catch (JsonSyntaxException e) {
                            e.printStackTrace(new PrintStream(sharedValues.getCallbacks().getStderr()));
                        }
                        return Boolean.TRUE;
                    }

                    @Override
                    public void done() {
                        //we don't need to do any cleanup so this is empty
                    }
                }.execute();

            }

            @Override
            public void onOpen(ServerHandshake handshake) {
                sharedValues.getCallbacks().printOutput("You are connected to ChatServer: " + getURI() + "\n");
                sharedValues.getBurpPanel().writeToAlertPane("Connected to server");
                getRoomsMessage();
            }

            @Override
            public void onClose(int code, String reason, boolean remote) {
                resetMutedClients();
                sharedValues.getCallbacks().printOutput("You have been disconnected from: " + getURI() + "; Code: " + code + " " + reason + "\n");
                if (code == CloseFrame.ABNORMAL_CLOSE) {
                    sharedValues.serverConnectionFailure(1);
                } else if (code != CloseFrame.NORMAL) {
                    if (reason.contains("401")) {
                        sharedValues.serverConnectionFailure(401);
                    } else if (reason.contains("409")) {
                        sharedValues.serverConnectionFailure(409);
                    }
                }
            }

            @Override
            public void onError(Exception ex) {
                sharedValues.getCallbacks().printOutput("Exception occured ...\n" + ex + "\n");
                if (ex instanceof SSLException) {
                    sharedValues.serverConnectionFailure(-4);
                } else if (ex instanceof ConnectException) {
                    sharedValues.serverConnectionFailure(-5);
                }
            }
        };
        SSLContext sslContext = getSSLContextFromLetsEncrypt();
        SSLSocketFactory factory = sslContext.getSocketFactory();
        cc.setSocketFactory(factory);
        cc.connect();
    }

    private void parseBurpTCMessage(BurpTCMessage burpTCMessage) {
        sharedValues.getCallbacks().printOutput("got: " + burpTCMessage +
                "\n");
        switch (burpTCMessage.getMessageType()) {
            case COOKIE_MESSAGE:
                if (this.sharedValues.getBurpPanel().getReceiveSharedCookiesSetting()) {
                    List<ICookie> newCookies = this.sharedValues.getGson().fromJson(burpTCMessage.getData(), SharedValues.cookieJsonListType);
                    for (ICookie newCookie : newCookies) {
                        this.sharedValues.getCallbacks().updateCookieJar(newCookie);
                    }
                }
                break;
            case SCAN_ISSUE_MESSAGE:
                this.sharedValues.getCallbacks().printOutput("Got new issue from client");
                ScanIssue decodedIssue = this.sharedValues.getGson().fromJson(burpTCMessage.getData(), ScanIssue.class);
                        /*
                        This hack is to bypass an infinite loop that occurs when I inject a new issue with addScanIssue()
                        and I also have a ScanListener setup. When I add an issue the Scanlistener activates which sends
                        out a new issue to addScanIssue.....You get the point. To bypass that, since passing a custom
                        ScanIssue to addScanIssue() looks no different than the internal one, I commandeer the remediation
                        value to set it to true. This is normally null in all the issues I've seen but if another
                        extension sets it to something meaningful this will clobber it. Sorry.
                         */
                decodedIssue.setRemediation();
                if (this.sharedValues.getBurpPanel().getReceiveSharedIssuesSetting()) {
                    this.sharedValues.getCallbacks().addScanIssue(decodedIssue);
                }
                break;
            case SYNC_SCOPE_MESSAGE:
                try {
                    this.sharedValues.getCallbacks().loadConfigFromJson(burpTCMessage.getData());
                } catch (Exception e) {
                    sharedValues.getCallbacks().printError(e.getMessage());
                }
                break;
            case BURP_MESSAGE:
                this.sharedValues.getCallbacks().addToSiteMap(burpTCMessage.getRequestResponse());
                break;
            case REPEATER_MESSAGE:
                this.sharedValues.getCallbacks().sendToRepeater(
                        burpTCMessage.getRequestResponse().getHttpService().getHost(),
                        burpTCMessage.getRequestResponse().getHttpService().getPort(),
                        burpTCMessage.getRequestResponse().getHttpService().getProtocol()
                                .equalsIgnoreCase("https"),
                        burpTCMessage.getRequestResponse().getRequest(),
                        "BurpTC Payload");
                break;
            case INTRUDER_MESSAGE:
                this.sharedValues.getCallbacks().sendToIntruder(
                        burpTCMessage.getRequestResponse().getHttpService().getHost(),
                        burpTCMessage.getRequestResponse().getHttpService().getPort(),
                        burpTCMessage.getRequestResponse().getHttpService().getProtocol()
                                .equalsIgnoreCase("https"),
                        burpTCMessage.getRequestResponse().getRequest());
                break;
            case NEW_MEMBER_MESSAGE:
                if (!SERVER.equals(this.currentRoom)) {
                    this.sharedValues.getRoomMembersListModel().removeAllElements();
                    for (String member : burpTCMessage.getData().split(",")) {
                        this.sharedValues.getRoomMembersListModel().addElement(member);
                    }
                }
                break;
            case GET_ROOMS_MESSAGE:
                this.sharedValues.getServerListModel().removeAllElements();
                if (burpTCMessage.getData().length() > 0) {
                    for (String member : burpTCMessage.getData().split(",")) {
                        String[] roomValues = member.split("::");
                        this.sharedValues.getServerListModel().addElement(new Room(roomValues[0], Boolean.valueOf(roomValues[1])));
                    }
                }
                break;
            case COMMENT_MESSAGE:
                HttpRequestResponse requestResponseWithComments = burpTCMessage.getRequestResponse();
                this.sharedValues.getRequestCommentModel().updateOrAddRequestResponse(requestResponseWithComments);
                break;
            case GET_COMMENTS_MESSAGE:
                Type listType = new TypeToken<ArrayList<HttpRequestResponse>>() {
                }.getType();
                List<HttpRequestResponse> httpRequestResponses = new Gson().fromJson(burpTCMessage.getData(), listType);
                for (HttpRequestResponse requestResponse : httpRequestResponses) {
                    this.sharedValues.getRequestCommentModel().updateOrAddRequestResponse(requestResponse);
                }
                break;
            case BAD_PASSWORD_MESSAGE:
                this.sharedValues.getBurpPanel().writeToAlertPane("Bad Room Password.");
                break;
            case GOOD_PASSWORD_MESSAGE:
                this.sharedValues.getBurpPanel().joinRoom();
            default:
                this.sharedValues.getCallbacks().printOutput("Bad msg type");
        }
    }


    void muteMember(String selectedValue) {
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.MUTE_MESSAGE,
                selectedValue, null);
        this.sendMessage(muteMessage);
        this.addMutedClient(selectedValue);
    }

    void unmuteMember(String selectedValue) {
        BurpTCMessage unmuteMessage = new BurpTCMessage(null, MessageType.UNMUTE_MESSAGE,
                selectedValue, null);
        this.sendMessage(unmuteMessage);
        this.removeMutedClient(selectedValue);
    }

    void createRoom(String roomName, String roomPassword) {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.ADD_ROOM_MESSAGE, roomName, roomPassword);
        this.currentRoom = roomName;
        this.sendMessage(newRoomMessage);
    }

    void leaveRoom() {
        BurpTCMessage newRoomMessage;
        newRoomMessage = new BurpTCMessage(null,
                MessageType.LEAVE_ROOM_MESSAGE, SERVER, null);
        this.sendMessage(newRoomMessage);
        this.currentRoom = SERVER;
    }

    void joinRoom(String roomName) {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.JOIN_ROOM_MESSAGE, roomName, null);
        this.currentRoom = roomName;
        this.sendMessage(newRoomMessage);
    }


    void checkRoomPassword(String roomName, String roomPassword) {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.CHECK_PASSWORD_MESSAGE, roomName, roomPassword);
        this.currentRoom = roomName;
        this.sendMessage(newRoomMessage);
    }

    private void getRoomsMessage() {
        BurpTCMessage getRoomsMessage = new BurpTCMessage(null,
                MessageType.GET_ROOMS_MESSAGE, "Self", null);
        this.sendMessage(getRoomsMessage);
    }

    void setRoomScope() {
        BurpTCMessage syncScopeMessage = new BurpTCMessage(null, MessageType.SYNC_SCOPE_MESSAGE, SharedValues.ROOM, this.sharedValues.getCurrentScope());
        this.sendMessage(syncScopeMessage);
    }

    void getRoomScope() {
        BurpTCMessage syncScopeMessage = new BurpTCMessage(null,
                MessageType.SYNC_SCOPE_MESSAGE, "Self", null);
        this.sendMessage(syncScopeMessage);
    }

    void muteAllMembers() {
        BurpTCMessage muteMessage = new BurpTCMessage(null,
                MessageType.MUTE_MESSAGE, "All", null);
        this.sendMessage(muteMessage);
    }

    void unmuteAllMembers() {
        BurpTCMessage muteMessage = new BurpTCMessage(null,
                MessageType.UNMUTE_MESSAGE, "All", null);
        this.sendMessage(muteMessage);
    }

    void sendMessage(BurpTCMessage burpTCMessage) {
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                if (!isPaused()) {
                    sharedValues.getCallbacks().printOutput("sending message: " + burpTCMessage);
                    cc.send(sharedValues.getCallbacks().getHelpers().base64Encode(sharedValues.getGson().toJson(burpTCMessage)));
                }
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
    }

    void sendCommentMessage(HttpRequestResponse requestResponseWithComments) {
        BurpTCMessage muteMessage = new BurpTCMessage(requestResponseWithComments,
                MessageType.COMMENT_MESSAGE, SharedValues.ROOM, Integer.toString(requestResponseWithComments.hashCode()));
        this.sendMessage(muteMessage);
    }

    private SSLContext getSSLContextFromLetsEncrypt() {
        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");

            byte[] certBytes =
                    parseDERFromPEM(Files.readAllBytes(sharedValues.getCertFile().toPath()),
                            "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
            byte[] keyBytes =
                    parseDERFromPEM(Files.readAllBytes(sharedValues.getCertKeyFile().toPath()),
                            "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");

            X509Certificate cert = generateCertificateFromDER(certBytes);
            RSAPrivateKey key = generatePrivateKeyFromDER(keyBytes);

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(null, null);
            keystore.setCertificateEntry("cert-alias", cert);
            keystore.setKeyEntry("key-alias", key, new char[]{}, new Certificate[]{cert});

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keystore);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keystore, new char[]{});

            KeyManager[] km = kmf.getKeyManagers();

            context.init(km, trustManagerFactory.getTrustManagers(), null);
        } catch (IOException | KeyManagementException | KeyStoreException | InvalidKeySpecException | UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException e) {
            sharedValues.getCallbacks().printError(e.getMessage());
            throw new IllegalArgumentException();
        }
        return context;
    }

    private byte[] parseDERFromPEM(byte[] pem, String beginDelimiter, String endDelimiter) {
        String data = new String(pem);
        String[] tokens = data.split(beginDelimiter);
        tokens = tokens[1].split(endDelimiter);
        return DatatypeConverter.parseBase64Binary(tokens[0]);
    }

    private RSAPrivateKey generatePrivateKeyFromDER(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) factory.generatePrivate(spec);
    }

    private static X509Certificate generateCertificateFromDER(byte[] certBytes) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    boolean isConnected() {
        return cc.isOpen();
    }

    void leaveServer() {
        cc.close();
    }

    String getCurrentRoom() {
        return this.currentRoom;
    }

    boolean isPaused() {
        return this.paused;
    }

    void pauseCommunication() {
        this.paused = true;
    }

    void unpauseCommunication() {
        this.paused = false;
    }

    String getUsername() {
        return username;
    }

    ArrayList<String> getMutedClients() {
        return mutedClients;
    }

    private void addMutedClient(String client) {
        mutedClients.add(client);
    }

    private void removeMutedClient(String client) {
        mutedClients.remove(client);
    }

    private void resetMutedClients() {
        mutedClients.clear();
    }
}