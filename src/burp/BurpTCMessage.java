package burp;

import com.google.gson.annotations.SerializedName;

public class BurpTCMessage {

    @SerializedName("burpmsg")
    private HttpRequestResponse requestResponse;
    @SerializedName("auth")
    private String authentication;
    @SerializedName("sender")
    private String sendingUser;
    @SerializedName("room")
    private String messageRoom;
    @SerializedName("receiver")
    private String messageTarget;
    @SerializedName("msgtype")
    private MessageType messageType;
    @SerializedName("data")
    private String data;

    public BurpTCMessage() {
    }

    public BurpTCMessage(HttpRequestResponse requestResponse, MessageType messageType,
                         String messageRoom, String messageTarget, String data) {
        this.requestResponse = requestResponse;
        this.messageType = messageType;
        this.messageRoom = messageRoom;
        this.messageTarget = messageTarget;
        this.data = data;
    }

    public String getMessageRoom() {
        return messageRoom;
    }

    public void setMessageRoom(String messageRoom) {
        this.messageRoom = messageRoom;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
    }

    public String getAuthentication() {
        return authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    public MessageType getMessageType() {
        return this.messageType;
    }

    public void setMessageType(MessageType messageType) {
        this.messageType = messageType;
    }

    public String getSendingUser() {
        return sendingUser;
    }

    public void setSendingUser(String sendingUser) {
        this.sendingUser = sendingUser;
    }

    public String getMessageTarget() {
        return this.messageTarget;
    }

    public void setMessageTarget(String messageTarget) {
        this.messageTarget = messageTarget;
    }

    @Override
    public String toString() {
        return "BurpTCMessage{" +
                "requestResponse=" + requestResponse +
                ", authentication='" + authentication + '\'' +
                ", sendingUser='" + sendingUser + '\'' +
                ", messageRoom='" + messageRoom + '\'' +
                ", messageTarget='" + messageTarget + '\'' +
                ", messageType=" + messageType +
                ", data='" + data + '\'' +
                '}';
    }
}
