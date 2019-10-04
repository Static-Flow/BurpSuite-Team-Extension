package teamExtension;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

public class RequestComment {
    ArrayList<RequestComment> replies; //all further comments on this one
    Date timeOfComment; //when the comment was made
    String comment; //the comment text
    String userWhoCommented; //the user who made the comment
    UUID commentID; //unique ID for comment

    public RequestComment() {
    }

    public RequestComment(String comment, String userWhoCommented) {
        this.comment = comment;
        this.replies = new ArrayList<>();
        this.timeOfComment = new Date();
        this.commentID = UUID.randomUUID();
        this.userWhoCommented = userWhoCommented;
    }

    public String getUserWhoCommented() {
        return userWhoCommented;
    }

    public void setUserWhoCommented(String userWhoCommented) {
        this.userWhoCommented = userWhoCommented;
    }

    public ArrayList<RequestComment> getReplies() {
        return replies;
    }

    public void addReply(RequestComment replyComment) {
        replies.add(replyComment);
    }

    public String getTimeOfComment() {

        SimpleDateFormat format = new SimpleDateFormat("MM-dd HH:mm:ss");
        return format.format(this.timeOfComment);
    }

    public void setTimeOfComment(Date timeOfComment) {
        this.timeOfComment = timeOfComment;
    }

    String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public UUID getCommentID() {
        return commentID;
    }

    public void setCommentID(UUID commentID) {
        this.commentID = commentID;
    }
}
