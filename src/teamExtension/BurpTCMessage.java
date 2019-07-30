package teamExtension;

import com.google.gson.annotations.SerializedName;

class BurpTCMessage {

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

    BurpTCMessage(HttpRequestResponse requestResponse, MessageType messageType,
                  String messageRoom, String messageTarget, String data) {
        this.requestResponse = requestResponse;
        this.messageType = messageType;
        this.messageRoom = messageRoom;
        this.messageTarget = messageTarget;
        this.data = data;
    }

    public String getData() {
        return data;
    }

    HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    String getAuthentication() {
        return authentication;
    }

    void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    MessageType getMessageType() {
        return this.messageType;
    }

    void setSendingUser(String sendingUser) {
        this.sendingUser = sendingUser;
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
