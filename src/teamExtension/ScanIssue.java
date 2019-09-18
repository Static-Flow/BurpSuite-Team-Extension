package teamExtension;

import burp.IScanIssue;

import java.net.URL;
import java.util.Arrays;

class ScanIssue implements IScanIssue {
    private final HttpService httpService;
    private final URL url;
    private final HttpRequestResponse[] httpMessages;
    private final String detail;
    private final String severity;
    private final String confidence;
    private String name;
    private String remediation; //There's no way to know if this class came from our tool or not so I need a flag that
    // exists on the interface. This is the flag I'm using. It's null normally anyways.

    ScanIssue(
            HttpService httpService,
            URL url,
            HttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
        this.remediation = remediation;
    }

    public void setName(String name) {
        this.name = name;
    }

    void setRemediation() {
        this.remediation = "true";
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public HttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public HttpService getHttpService() {
        return httpService;
    }

    @Override
    public String toString() {
        return "ScanIssue{" +
                "httpService=" + httpService +
                ", url=" + url +
                ", httpMessages=" + Arrays.toString(httpMessages) +
                ", name='" + name + '\'' +
                ", detail='" + detail + '\'' +
                ", severity='" + severity + '\'' +
                ", confidence='" + confidence + '\'' +
                ", remediation='" + remediation + '\'' +
                '}';
    }
}