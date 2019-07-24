package burp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class ServerConnector {
    private String serverAddress;
    private int serverPort;
    private String yourName;
    private String serverPassword;
    private String currentRoom;
    private String currentRoomKey;
    private SharedValues sharedValues;
    private BlockingQueue<String> messg;
    private ServerWriteThread writer;
    private ServerListenThread listener;
    private Thread listenerThread;


    public ServerConnector(String serverAddress, int serverPort, String yourName,
                           String serverPassword, PrintWriter printWriter,
                           SharedValues sharedValues) {
        System.out.println("Establishing connection. Please wait ...");
        this.messg = new LinkedBlockingQueue<>(1);
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.serverPassword = serverPassword;
        this.yourName = yourName;
        this.sharedValues = sharedValues;
        this.sharedValues.initAESCrypterWithKey(serverPassword);
    }

    public void authenticate(String destination)
            throws LoginFailedException, IOException {
        System.out.println("Authenticating");
        Socket socket = new Socket(this.serverAddress, this.serverPort);
        PrintWriter streamOut = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader streamIn = new BufferedReader(new InputStreamReader(socket.getInputStream
                ()));
        BurpTCMessage loginMessage = new BurpTCMessage(null,
                MessageType.LOGIN_MESSAGE, destination, null, null);
        loginMessage.setAuthentication(this.getServerPassword());
        loginMessage.setSendingUser(this.getYourName());
        String encryptedMessage;
        try {
            encryptedMessage = this.sharedValues.getAESCrypter().encrypt(
                    this.sharedValues.getGson().toJson(loginMessage)
            );
            System.out.println(this.sharedValues.getAESCrypter().decrypt(encryptedMessage));
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
                this.currentRoom = destination;
                this.sharedValues.initAESCrypterWithKey(loginMessage.getAuthentication());
                this.writer = new ServerWriteThread(socket,
                        this.yourName, this.serverPassword, this.messg);
                this.listener = new ServerListenThread(socket,
                        sharedValues);
                Thread writerThread = new Thread(writer);
                this.listenerThread = new Thread(listener);
                listenerThread.start();
                writerThread.start();
                System.out.println("Connected: " + socket);
            } else {
                throw new LoginFailedException();
            }
        } else {
            throw new LoginFailedException();
        }
    }

    public String getCurrentRoomKey() {
        return currentRoomKey;
    }

    public void setCurrentRoomKey(String currentRoomKey) {
        this.currentRoomKey = currentRoomKey;
    }

    public void getServerRooms() {
        this.sendMessage(new BurpTCMessage(null, MessageType.GET_ROOMS_MESSAGE, null, "me", null));
    }

    public String getYourName() {
        return yourName;
    }

    public String getServerPassword() {
        return this.serverPassword;
    }

    public void sendMessage(BurpTCMessage message) {
        try {
            message.setAuthentication(this.getServerPassword());
            message.setSendingUser(this.getYourName());
            String encryptedMsg = this.sharedValues.getAESCrypter().encrypt(
                    this.sharedValues.getGson().toJson(message));
            this.messg.put(encryptedMsg);
            System.out.println("Outside messg count" + this.messg.size());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void leave() {
        System.out.println("leaving server");
        BurpTCMessage leavingMessage = new BurpTCMessage(null,
                MessageType.QUIT_MESSAGE, this.currentRoom, "room", null);
        this.sendMessage(leavingMessage);
        cutTheHardLine();
    }

    public Thread getListener() {
        return this.listenerThread;
    }

    public void cutTheHardLine() {
        this.writer.stop();
        this.listener.stop();
    }

    public void muteMember(String selectedValue) {
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.MUTE_MESSAGE, this.currentRoom,
                selectedValue, null);
        this.sendMessage(muteMessage);
    }

    public void unmuteMember(String selectedValue) {
        BurpTCMessage unmuteMessage = new BurpTCMessage(null, MessageType.UNMUTE_MESSAGE, this.currentRoom,
                selectedValue, null);
        this.sendMessage(unmuteMessage);
    }

    public String getCurrentRoom() {
        return this.currentRoom;
    }

    public void createRoom(String roomName) {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.ADD_ROOM_MESSAGE, roomName, this.currentRoom, null);
        this.currentRoom = roomName;
        this.sendMessage(newRoomMessage);
    }

    public void leaveRoom() {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.LEAVE_ROOM_MESSAGE, this.currentRoom, null, null);
        this.sendMessage(newRoomMessage);
        this.currentRoom = "server";
    }

    public void joinRoom(String roomName) {
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.JOIN_ROOM_MESSAGE, roomName, this.currentRoom, null);
        this.currentRoom = roomName;
        this.sendMessage(newRoomMessage);
    }
}
