package teamextension;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerListener;

import java.util.ArrayList;

public class ScannerListener implements IScannerListener {

    private final SharedValues sharedValues;

    public ScannerListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    /*
        This is the grossest part of the extension and I apologize ahead of time. When you extend interfaces in Burp
        and pass then to methods like this Burp doesn't see them as Class Foo extends Bar. It sees them as a whole
        separate class in a different package. What this means is that I can't differentiate between the custom ScanIssue
        I pass to this method and the one that comes internally when Burp finds a new issue. So to bypass an infinite
        loop that will occur when I add a new Scan Issue from another client and it trips this method I check whether
        issue.GetRemediation() is not null (the case if it comes from inside Burp) or "true" (which is what I set it to).
     */
    @Override
    public void newScanIssue(IScanIssue issue) {
        if (this.sharedValues.getClient().isConnected() && this.sharedValues.getBurpPanel().inRoom() &&
                this.sharedValues.getBurpPanel().getShareIssuesSetting()) {
            sharedValues.getCallbacks().printOutput("New issue");
            ArrayList<HttpRequestResponse> httpMessages = new ArrayList<>();
            for (IHttpRequestResponse httpRequestResponse : issue.getHttpMessages()) {
                httpMessages.add(new HttpRequestResponse(httpRequestResponse));
                HttpRequestResponse[] httpRequestResponses = new HttpRequestResponse[httpMessages.size()];
                ScanIssue decodedIssue = new ScanIssue(new HttpService(issue.getHttpService()),
                        issue.getUrl(), httpMessages.toArray(httpRequestResponses),
                        issue.getIssueName(), issue.getIssueDetail(), issue.getSeverity(),
                        issue.getConfidence(), issue.getRemediationDetail());
                if (decodedIssue.getRemediationDetail() == null || !decodedIssue.getRemediationDetail().equals("true")) {
                    sharedValues.getClient().sendMessage(new BurpTCMessage(null,
                            MessageType.SCAN_ISSUE_MESSAGE, SharedValues.ROOM,
                            this.sharedValues.getGson().toJson(decodedIssue)));
                }
            }
        }
    }
}
