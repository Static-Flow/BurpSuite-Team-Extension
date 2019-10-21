package teamextension;

import java.text.SimpleDateFormat;
import java.util.Date;

public class RequestComment {
    Date timeOfComment; //when the comment was made
    String comment; //the comment text
    String userWhoCommented; //the user who made the comment

    RequestComment(String comment, String userWhoCommented) {
        this.comment = comment;
        this.timeOfComment = new Date();
        this.userWhoCommented = userWhoCommented;
    }

    String getUserWhoCommented() {
        return userWhoCommented;
    }

    public void setUserWhoCommented(String userWhoCommented) {
        this.userWhoCommented = userWhoCommented;
    }

    String getTimeOfComment() {

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
}
