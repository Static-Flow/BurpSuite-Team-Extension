package teamextension;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

class RequestCommentModel extends AbstractListModel {

    private ArrayList<HttpRequestResponse> requestResponsesWithComments;
    private SharedValues sharedValues;
    private ArrayList<CommentFrame> openCommentSessions;

    RequestCommentModel(SharedValues sharedValues) {
        requestResponsesWithComments = new ArrayList<>();
        openCommentSessions = new ArrayList<>();
        this.sharedValues = sharedValues;
    }

    void clearValues() {
        this.requestResponsesWithComments.clear();
        fireContentsChanged(this, 0, 0);
    }

    void addCommentToNewOrExistingReqResp(RequestComment comment, HttpRequestResponse possibleRequestResponse) {
        if (this.requestResponsesWithComments.contains(possibleRequestResponse)) {
            int foundIndex = this.requestResponsesWithComments.indexOf(possibleRequestResponse);
            this.requestResponsesWithComments.get(foundIndex).addComment(comment);
            fireContentsChanged(this, foundIndex,foundIndex);
        } else {
            possibleRequestResponse.addComment(comment);
            this.requestResponsesWithComments.add(possibleRequestResponse);
            fireContentsChanged(this, 0,
                    this.requestResponsesWithComments.size());
        }
        sharedValues.getClient().sendCommentMessage(possibleRequestResponse);
        this.contentChanged();
    }

    void removeCommentFromNewOrExistingReqResp(RequestComment comment,
                                        HttpRequestResponse possibleRequestResponse) {
        HttpRequestResponse requestResponseToEdit =
                this.requestResponsesWithComments.get(this.requestResponsesWithComments.indexOf(possibleRequestResponse));
        requestResponseToEdit.getComments().remove(comment);
        sharedValues.getCallbacks().printOutput("Removed comment: "+requestResponseToEdit);
        if(requestResponseToEdit.getComments().size() == 0) {
            this.requestResponsesWithComments.remove(requestResponseToEdit);
        }
        fireIntervalRemoved(this,0,this.requestResponsesWithComments.size());
        sharedValues.getClient().sendCommentMessage(requestResponseToEdit);
        this.contentChanged();
    }

    private void contentChanged() {
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                JTabbedPane burpTab = ((JTabbedPane) sharedValues.getBurpPanel().getParent());
                burpTab.setBackgroundAt(
                        burpTab.indexOfTab(SharedValues.EXTENSION_NAME),
                        new Color(0xff6633)
                );
                JTabbedPane optionsPane = sharedValues.getBurpPanel().getOptionsPane();
                optionsPane.setForegroundAt(
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

    /*
    This loops through all open comment panels and finds the one which
    contains our newly changed HttpRequestResponse with updated comment info
     */
    private void updateCommentSessions(HttpRequestResponse httpRequestResponse) {
        for (CommentFrame commentSession : this.openCommentSessions) {
            if (commentSession.getRequestResponse().equals(httpRequestResponse)) {
                commentSession.setRequestResponse(httpRequestResponse);
            }
        }
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
        if( requestResponse.getComments().size() > 0) {
            if (url.length() > 120) {
                return requestResponse.getComments().get(0).getUserWhoCommented() +
                        " Started a thread about " +
                        url.substring(0, 120) + "..." +
                        " with " + requestResponse.getComments().size() + " Comments";
            } else {
                return requestResponse.getComments().get(0).getUserWhoCommented() +
                        " Started a thread about " + url + " with " +
                        requestResponse.getComments().size() + " Comments";
            }
        } else  {
            return "";
        }
    }

    void updateOrAddRequestResponse(HttpRequestResponse requestResponseWithComments) {
        sharedValues.getCallbacks().printOutput(requestResponseWithComments.toString());
        if (this.requestResponsesWithComments.contains(requestResponseWithComments)) {
            sharedValues.getCallbacks().printOutput("Found existing comment");
            int changingIndex =
                    this.requestResponsesWithComments.indexOf(requestResponseWithComments);
            if(requestResponseWithComments.getComments().size() == 0) {
                sharedValues.getCallbacks().printOutput("No more comments. " +
                        "Removing.");
                // There are no more comments delete this from the model
                this.requestResponsesWithComments.remove(requestResponseWithComments);
                fireIntervalRemoved(this,0,this.requestResponsesWithComments.size());
            } else {
                sharedValues.getCallbacks().printOutput("Updating comment");
                this.requestResponsesWithComments.set(changingIndex, requestResponseWithComments);
                fireContentsChanged(this, changingIndex, changingIndex);
            }
            contentChanged();
        } else {
            sharedValues.getCallbacks().printOutput("New comment, adding " +
                    "to model.");
            this.requestResponsesWithComments.add(requestResponseWithComments);
            fireContentsChanged(this,0,this.requestResponsesWithComments.size());
            contentChanged();
        }
        updateCommentSessions(requestResponseWithComments);
    }

    void removeCommentSession(CommentFrame commentSession) {
        this.openCommentSessions.remove(commentSession);
        sharedValues.getCallbacks().printOutput("Removed a commentSession for" +
                " a total of " + getCommentSessions().size());
    }

    void addCommentSession(CommentFrame commentFrame) {
        this.openCommentSessions.add(commentFrame);

        sharedValues.getCallbacks().printOutput("Added new commentSession for" +
                " a total of " + getCommentSessions().size());
    }

    ArrayList<CommentFrame> getCommentSessions() {
        return this.openCommentSessions;
    }
}