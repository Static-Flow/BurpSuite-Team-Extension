package teamextension;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.List;

class CommentFrame {

    private final HttpRequestResponse requestResponse;
    private final IBurpExtenderCallbacks callbacks;
    private final String userWhoInitiated;

    CommentFrame(IBurpExtenderCallbacks callbacks, HttpRequestResponse requestResponse, String userWhoInitiated) {
        this.callbacks = callbacks;
        this.requestResponse = requestResponse;
        this.userWhoInitiated = userWhoInitiated;
        init();
    }

    private void init() {
        JFrame frame = new JFrame();
        JPanel topPane = new JPanel(new BorderLayout());
        JSplitPane splitter = new JSplitPane();
        splitter.setDividerLocation(750);
        splitter.setOrientation(JSplitPane.VERTICAL_SPLIT);
        JTabbedPane reqRespTabbedPane = new JTabbedPane();
        IMessageEditor requestMessageToDisplay = callbacks.createMessageEditor(
                new MessageEditorController(
                        requestResponse.getHttpService(),
                        requestResponse.getRequest(),
                        requestResponse.getResponse()),
                false);
        requestMessageToDisplay.setMessage(requestResponse.getRequest(), true);
        IMessageEditor responseMessageToDisplay = callbacks.createMessageEditor(
                new MessageEditorController(
                        requestResponse.getHttpService(),
                        requestResponse.getRequest(),
                        requestResponse.getResponse()),
                false);
        responseMessageToDisplay.setMessage(requestResponse.getResponse(), true);
        reqRespTabbedPane.addTab("Request", requestMessageToDisplay.getComponent());
        reqRespTabbedPane.addTab("Response", responseMessageToDisplay.getComponent());
        splitter.setTopComponent(reqRespTabbedPane);

        CommentsPanel commentsPanel = new CommentsPanel();
        if (!requestResponse.getComments().isEmpty()) {
            commentsPanel.layoutComments(requestResponse.getComments());
        }
        splitter.setBottomComponent(commentsPanel);
        topPane.add(splitter, BorderLayout.CENTER);

        JPanel addCommentPanel = new JPanel(new BorderLayout());
        JTextArea commentArea = new JTextArea(3, 50);
        commentArea.setLineWrap(true);
        commentArea.setWrapStyleWord(true);
        JScrollPane commentAreaScroller = new JScrollPane(commentArea);
        commentArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    if (e.isShiftDown()) {
                        commentArea.setText(commentArea.getText() + "\n");
                    } else {
                        requestResponse.setHighlight("cyan");
                        RequestComment newComment = new RequestComment(commentArea.getText().trim(), userWhoInitiated);
                        requestResponse.addComment(newComment);
                        commentArea.setText("");
                        commentsPanel.addComment(newComment);
                    }
                }
            }
        });
        addCommentPanel.add(commentAreaScroller, BorderLayout.CENTER);
        topPane.add(addCommentPanel, BorderLayout.PAGE_END);

        frame.add(topPane, BorderLayout.CENTER);
        frame.setSize(400, 750);
        frame.pack();
        frame.setVisible(true);

    }
}

class CommentsPanel extends JScrollPane {

    private JPanel topPane;
    private GridBagConstraints c;

    CommentsPanel() {
        setPreferredSize(new Dimension(400, 700));
        topPane = new JPanel(new GridBagLayout());
        topPane.setBackground(Color.blue);
        c = new GridBagConstraints();
        c.gridy = GridBagConstraints.PAGE_END;
        c.gridx = 0;
        c.weightx = 1;
        c.weighty = 1;
        c.anchor = GridBagConstraints.PAGE_END;
        c.fill = GridBagConstraints.BOTH;
        c.gridheight = GridBagConstraints.REMAINDER;
        c.gridwidth = GridBagConstraints.REMAINDER;
        topPane.add(new JPanel(), c);

        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = GridBagConstraints.RELATIVE;
        c.weightx = 1;
        c.weighty = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.PAGE_START;
        c.gridwidth = GridBagConstraints.REMAINDER;
        setViewportView(topPane);
    }

    void addComment(RequestComment comment) {

        topPane.add(new CommentPanel(comment), c, topPane.getComponentCount() - 1);
        revalidate();
    }

    void layoutComments(List<RequestComment> comments) {
        for (RequestComment comment : comments) {
            topPane.add(new CommentPanel(comment), c, topPane.getComponentCount() - 1);
        }
        revalidate();
    }
}

class CommentPanel extends JPanel {

    CommentPanel(RequestComment comment) {
        setLayout(new BorderLayout());
        setSize(new Dimension(400, 120));
        JPanel statusPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPane.add(new JLabel(comment.getUserWhoCommented() + " - " + comment.getTimeOfComment()));
        add(statusPane, BorderLayout.PAGE_START);
        add(new JLabel(comment.getComment()), BorderLayout.CENTER);
    }

}