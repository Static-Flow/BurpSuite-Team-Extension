package teamExtension;

import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.util.ArrayList;
import java.util.Arrays;

public class HttpRequestResponse implements IHttpRequestResponse
{

    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private HttpService httpService;
    private transient ArrayList<RequestComment> comments;

    public HttpRequestResponse() {
    }

    HttpRequestResponse(IHttpRequestResponse copy) {
        this.request = copy.getRequest();
        this.response = copy.getResponse();
        this.comment = copy.getComment();
        this.highlight = copy.getHighlight();
        this.httpService = new HttpService(copy.getHttpService());
        this.comments = new ArrayList<>();
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        request = message;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        response = message;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        this.highlight = color;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = new HttpService(httpService);
    }

    @Override
    public String toString() {
        return "HttpRequestResponse{" +
                "request=" + Arrays.toString(request) +
                ", response=" + Arrays.toString(response) +
                ", comment='" + comment + '\'' +
                ", highlight='" + highlight + '\'' +
                ", httpService=" + httpService +
                '}';
    }

    public void addComment(RequestComment comment) {
        this.comments.add(comment);
    }

    public ArrayList<RequestComment> getComments() {
        return this.comments;
    }

    public boolean hasComments() {
        return this.comments.size() > 0;
    }
}
