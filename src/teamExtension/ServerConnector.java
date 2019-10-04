package teamExtension;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

class ServerConnector {
    private static final String ME = "me";
    private static final String ALL = "all";
    public final String SERVER = "server";
    private final String serverAddress;
    private final int serverPort;
    private final String yourName;
    private final String serverPassword;
    private String currentRoom;
    private final SharedValues sharedValues;
    private final BlockingQueue<String> messageQueue;
    private ServerWriteThread writer;
    private ServerListenThread listener;
    private Thread listenerThread;

    ServerConnector(String serverAddress, int serverPort, String yourName,
                    String serverPassword, SharedValues sharedValues) {
        System.out.println("Establishing connection. Please wait ...");
        this.messageQueue = new LinkedBlockingQueue<>(1);
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.serverPassword = serverPassword;
        this.yourName = yourName;
        this.sharedValues = sharedValues;
        this.sharedValues.initAESCrypterWithKey(serverPassword);
    }

    void authenticate()
            throws LoginFailedException, IOException, DuplicateNameException {
        System.out.println("Authenticating");
        Socket socket = new Socket(this.serverAddress, this.serverPort);
        PrintWriter streamOut = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader streamIn = new BufferedReader(new InputStreamReader(socket.getInputStream
                ()));
        BurpTCMessage loginMessage = new BurpTCMessage(null,
                MessageType.LOGIN_MESSAGE, SERVER, null, null);
        loginMessage.setAuthentication(this.getServerPassword());
        loginMessage.setSendingUser(this.getYourName());
        String encryptedMessage;
        try {
            encryptedMessage = this.sharedValues.getAESCrypter().encrypt(
                    this.sharedValues.getGson().toJson(loginMessage)
            );
        } catch (Exception e) {
            e.printStackTrace();
            throw new LoginFailedException();
        }
        if (encryptedMessage != null) {
            streamOut.println(encryptedMessage);
            streamOut.flush();
            BurpTCMessage loginResponse = this.sharedValues.getGson().fromJson(
                    this.sharedValues.getAESCrypter().decrypt(streamIn.readLine()), BurpTCMessage.class);
            System.out.println(loginResponse);
            if (loginResponse.getAuthentication().trim().equals("SUCCESS")) {
                this.currentRoom = SERVER;
                this.sharedValues.initAESCrypterWithKey(loginMessage.getAuthentication());
                this.writer = new ServerWriteThread(socket, this.messageQueue);
                this.listener = new ServerListenThread(socket,
                        sharedValues);
                Thread writerThread = new Thread(writer);
                this.listenerThread = new Thread(listener);
                listenerThread.start();
                writerThread.start();
                System.out.println("Connected: " + socket);
            } else if (loginResponse.getAuthentication().trim().equals("DUPLICATE")) {
                throw new DuplicateNameException();
            } else {
                throw new LoginFailedException();
            }
        } else {
            throw new LoginFailedException();
        }
    }

    void getServerRooms() {
        this.sendMessage(new BurpTCMessage(null, MessageType.GET_ROOMS_MESSAGE, null, ME, null));
    }

    String getYourName() {
        return yourName;
    }

    private String getServerPassword() {
        return this.serverPassword;
    }

    void sendMessage(BurpTCMessage message) {
        try {
            message.setAuthentication(this.getServerPassword());
            message.setSendingUser(this.getYourName());
            String encryptedMsg = this.sharedValues.getAESCrypter().encrypt(
                    this.sharedValues.getGson().toJson(message));
            this.messageQueue.put(encryptedMsg);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void leave() {
        System.out.println("leaving server");
        BurpTCMessage leavingMessage = new BurpTCMessage(null,
                MessageType.QUIT_MESSAGE, this.currentRoom, SharedValues.ROOM, null);
        this.sendMessage(leavingMessage);
        cutTheHardLine();
    }

    Thread getListener() {
        return this.listenerThread;
    }

    void cutTheHardLine() {
        this.writer.stop();
        this.listener.stop();
    }

    void muteMember(String selectedValue) {
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.MUTE_MESSAGE, this.currentRoom,
                selectedValue, null);
        this.sendMessage(muteMessage);
    }

    void unmuteMember(String selectedValue) {
        BurpTCMessage unmuteMessage = new BurpTCMessage(null, MessageType.UNMUTE_MESSAGE, this.currentRoom,
                selectedValue, null);
        this.sendMessage(unmuteMessage);
    }

    String getCurrentRoom() {
        return this.currentRoom;
    }

    void createRoom(String roomName) {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.ADD_ROOM_MESSAGE, roomName, null, null);
        this.currentRoom = roomName;
        this.sendMessage(newRoomMessage);
    }

    void leaveRoom() {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.LEAVE_ROOM_MESSAGE, this.currentRoom, null, null);
        this.sendMessage(newRoomMessage);
        this.currentRoom = SERVER;
    }

    void joinRoom(String roomName) {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.JOIN_ROOM_MESSAGE, roomName, null, null);
        this.currentRoom = roomName;
        this.sendMessage(newRoomMessage);
    }

    void setRoomScope() {
        BurpTCMessage syncScopeMessage = new BurpTCMessage(null, MessageType.SYNC_SCOPE_MESSAGE, this.currentRoom, SharedValues.ROOM, this.sharedValues.getCurrentScope());
        this.sendMessage(syncScopeMessage);
    }

    void getRoomScope() {
        BurpTCMessage syncScopeMessage = new BurpTCMessage(null, MessageType.SYNC_SCOPE_MESSAGE, this.currentRoom, ME, null);
        this.sendMessage(syncScopeMessage);
    }

    void muteAllMembers() {
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.MUTE_MESSAGE, this.currentRoom,
                ALL, null);
        this.sendMessage(muteMessage);
    }

    void unmuteAllMembers() {
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.UNMUTE_MESSAGE, this.currentRoom,
                ALL, null);
        this.sendMessage(muteMessage);
    }
}
