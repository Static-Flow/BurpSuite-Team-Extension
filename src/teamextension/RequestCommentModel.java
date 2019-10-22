package teamextension;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

class RequestCommentModel extends AbstractListModel {

    private ArrayList<HttpRequestResponse> requestResponsesWithComments;
    private SharedValues sharedValues;

    RequestCommentModel(SharedValues sharedValues) {
        requestResponsesWithComments = new ArrayList<>();
        this.sharedValues = sharedValues;
    }

    void addCommentToNewOrExistingReqResp(RequestComment comment, HttpRequestResponse possibleRequestResponse) {
        if (this.requestResponsesWithComments.contains(possibleRequestResponse)) {
            int foundIndex = this.requestResponsesWithComments.indexOf(possibleRequestResponse);
            this.requestResponsesWithComments.get(foundIndex).addComment(comment);
            this.contentChanged(foundIndex);
        } else {
            possibleRequestResponse.addComment(comment);
            this.requestResponsesWithComments.add(possibleRequestResponse);
            this.contentChanged(this.requestResponsesWithComments.size() - 1);
        }
    }

    private void contentChanged(int index) {
        fireContentsChanged(this, index, index);
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                JTabbedPane burpTab = ((JTabbedPane) sharedValues.getBurpPanel().getParent());
                burpTab.setBackgroundAt(
                        burpTab.indexOfTab(SharedValues.EXTENSION_NAME),
                        new Color(0xff6633)
                );
                JTabbedPane optionsPane = sharedValues.getBurpPanel().getOptionsPane();
                optionsPane.setBackgroundAt(
                        optionsPane.indexOfTab("Comments"),
                        new Color(0xff6633)
                );
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
    }

    HttpRequestResponse findRequestResponseWithComments(HttpRequestResponse possibleRequestResponse) {
        if (this.requestResponsesWithComments.contains(possibleRequestResponse)) {
            return this.requestResponsesWithComments.get(this.requestResponsesWithComments.indexOf(possibleRequestResponse));
        } else {
            return null;
        }
    }

    @Override
    public int getSize() {
        return requestResponsesWithComments.size();
    }

    HttpRequestResponse getTrueElementAt(int index) {
        return requestResponsesWithComments.get(index);
    }

    @Override
    public String getElementAt(int index) {
        HttpRequestResponse requestResponse = requestResponsesWithComments.get(index);
        String url = sharedValues.getCallbacks().getHelpers().analyzeRequest(requestResponse).getUrl().toString();
        return requestResponse.getComments().get(0).getUserWhoCommented() +
                " Started a thread about " +
                url.substring(0, 30) + "..." +
                " with " + requestResponse.getComments().size() + " Comments";
    }

    void updateOrAddRequestResponse(HttpRequestResponse requestResponseWithComments) {
        sharedValues.getCallbacks().printOutput(requestResponseWithComments.toString());
        if (this.requestResponsesWithComments.contains(requestResponseWithComments)) {
            this.requestResponsesWithComments.set(this.requestResponsesWithComments.indexOf(requestResponseWithComments), requestResponseWithComments);
            contentChanged(this.requestResponsesWithComments.indexOf(requestResponseWithComments));
        } else {
            this.requestResponsesWithComments.add(requestResponseWithComments);
            contentChanged(this.requestResponsesWithComments.size() - 1);
        }

    }
}