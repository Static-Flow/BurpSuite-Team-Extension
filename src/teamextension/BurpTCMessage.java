package teamextension;

import com.google.gson.annotations.SerializedName;

class BurpTCMessage {

    @SerializedName("burpmsg")
    private HttpRequestResponse requestResponse;
    @SerializedName("messageTarget")
    private String messageTarget;
    @SerializedName("msgtype")
    private MessageType messageType;
    @SerializedName("data")
    private String data;

    BurpTCMessage(HttpRequestResponse requestResponse, MessageType messageType,
                  String messageTarget, String data) {
        this.requestResponse = requestResponse;
        this.messageType = messageType;
        this.messageTarget = messageTarget;
        this.data = data;
    }

    String getData() {
        return data;
    }

    HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }


    MessageType getMessageType() {
        return this.messageType;
    }


    @Override
    public String toString() {
        return "BurpTCMessage{" +
                "requestResponse=" + requestResponse +
                ", messageTarget='" + messageTarget + '\'' +
                ", messageType=" + messageType +
                ", data='" + data + '\'' +
                '}';
    }
}
