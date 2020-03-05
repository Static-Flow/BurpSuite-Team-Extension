package teamextension;

class SharedRequest {
    private HttpRequestResponse requestResponse;
    private String datetime;

    SharedRequest(HttpRequestResponse burpMessage, String datetime) {
        this.requestResponse = burpMessage;
        this.datetime = datetime;
    }

    HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    String getDatetime() {
        return datetime;
    }

}
