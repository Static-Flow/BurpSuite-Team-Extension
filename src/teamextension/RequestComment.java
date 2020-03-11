package teamextension;

import javax.swing.*;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;

public class RequestComment extends JPanel {
    private Date timeOfComment; //when the comment was made
    private String comment; //the comment text
    private String userWhoCommented; //the user who made the comment

    RequestComment(String comment, String userWhoCommented, Date timeOfComment) {
        super();
        this.comment = comment;
        this.timeOfComment = timeOfComment;
        this.userWhoCommented = userWhoCommented;
        System.out.println(comment+":"+timeOfComment+":"+userWhoCommented);
        setLayout(new BorderLayout());
        setSize(new Dimension(400, 120));
        JPanel statusPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel commentText =
                new JLabel(this.userWhoCommented + " - " + this.getTimeOfComment());
        statusPane.add(commentText);
        add(statusPane, BorderLayout.PAGE_START);
        add(new JLabel(this.comment), BorderLayout.CENTER);
    }

    String getUserWhoCommented() {
        return userWhoCommented;
    }

    public void setUserWhoCommented(String userWhoCommented) {
        this.userWhoCommented = userWhoCommented;
    }

    String getTimeOfComment() {

        SimpleDateFormat format = new SimpleDateFormat("MMM dd HH:mm:ss");
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

    @Override
    public String toString() {
        return "RequestComment{" +
                "timeOfComment=" + this.getTimeOfComment() +
                ", comment='" + comment + '\'' +
                ", userWhoCommented='" + userWhoCommented + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RequestComment that = (RequestComment) o;
        return timeOfComment.equals(that.timeOfComment) &&
                comment.equals(that.comment) &&
                userWhoCommented.equals(that.userWhoCommented);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timeOfComment, comment, userWhoCommented);
    }
}
