package teamextension;

import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HttpRequestResponse implements IHttpRequestResponse
{

    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private HttpService httpService;
    private List<RequestComment> comments;

    public HttpRequestResponse() {
    }

    public HttpRequestResponse(IHttpRequestResponse copy) {
        this.request = copy.getRequest();
        this.response = copy.getResponse();
        this.comment = copy.getComment();
        this.highlight = copy.getHighlight();
        this.httpService = new HttpService(copy.getHttpService());
        this.comments = new ArrayList<>();
    }

    @Override
    public byte[] getRequest() {
        if(request == null) {
            return new byte[]{};
        }
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        request = message;
    }

    @Override
    public byte[] getResponse() {
        if(response == null) {
            return new byte[]{};
        }
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
                ", comments=" + Arrays.toString(comments.toArray()) +
                '}';
    }

    void addComment(RequestComment comment) {
        this.comments.add(comment);
    }

    List<RequestComment> getComments() {
        return this.comments;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HttpRequestResponse that = (HttpRequestResponse) o;
        return Arrays.equals(request, that.request) &&
                Arrays.equals(response, that.response);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(request);
        result = 31 * result + Arrays.hashCode(response);
        return result;
    }
}
