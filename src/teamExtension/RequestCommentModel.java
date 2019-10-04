package teamExtension;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;

public class RequestCommentModel extends DefaultListModel<HttpRequestResponse> {

    private final IBurpExtenderCallbacks callbacks;

    RequestCommentModel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    HttpRequestResponse findRequestWithCommentsByUrl(URL url) {
        while (this.elements().hasMoreElements()) {
            HttpRequestResponse requestResponse = this.elements().nextElement();
            if (this.callbacks.getHelpers().analyzeRequest(requestResponse).getUrl().equals(url)) {
                return requestResponse;
            }
        }
        return null;
    }

    ArrayList<RequestComment> getCommentsFromRequest(HttpRequestResponse requestResponse) {
        return requestResponse.getComments();
    }

    ArrayList<HttpRequestResponse> getComments() {
        return Collections.list(this.elements());
    }

}
