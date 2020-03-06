package teamextension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

class SharedRequest {
    private HttpRequestResponse requestResponse;
    private String datetime;
    private String link;

    SharedRequest(HttpRequestResponse burpMessage, String datetime) throws IOException {
        this.requestResponse = burpMessage;
        this.datetime = datetime;
        byte[] rawBytes = stripBurpMessage(burpMessage);
        this.link = "burptcmessage/" +
                        Base64.getEncoder().encodeToString(compress(new String(rawBytes)));
    }

    SharedRequest(String link, String datetime) {
        this.datetime = datetime;
        this.link = "burptcmessage/shortener/"+link;
    }

    HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    String getLink() {
        return link;
    }

    String getDatetime() {
        return datetime;
    }

    private static byte[] compress(String data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length());
        GZIPOutputStream gzip = new GZIPOutputStream(bos);
        gzip.write(data.getBytes());
        gzip.close();
        byte[] compressed = bos.toByteArray();
        bos.close();
        return compressed;
    }

    private byte[] stripBurpMessage(HttpRequestResponse burpMessage) throws IOException {
        ByteArrayOutputStream myStream = new ByteArrayOutputStream();
        byte divider = (byte) 127;
        myStream.write(burpMessage.getRequest());
        myStream.write(divider);
        myStream.write(burpMessage.getResponse());
        myStream.write(divider);
        myStream.write(burpMessage.getHttpService().getHost().getBytes());
        myStream.write(divider);
        myStream.write(Integer.toString(burpMessage.getHttpService().getPort()).getBytes());
        myStream.write(divider);
        myStream.write(burpMessage.getHttpService().getProtocol().getBytes());

        return myStream.toByteArray();
    }

}
