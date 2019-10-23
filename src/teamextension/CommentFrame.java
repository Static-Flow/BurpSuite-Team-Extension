package teamextension;

import burp.IMessageEditor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

class CommentFrame {

    private HttpRequestResponse requestResponse;
    private SharedValues sharedValues;
    private final String userWhoInitiated;
    private CommentsPanel commentsPanel;
    private JFrame frame;

    CommentFrame(SharedValues sharedValues, HttpRequestResponse requestResponse, String userWhoInitiated) {
        this.sharedValues = sharedValues;
        this.requestResponse = requestResponse;
        this.userWhoInitiated = userWhoInitiated;
        init(this);
    }

    void close() {
        sharedValues.getRequestCommentModel().removeCommentSession(this);
        frame.dispose();
    }

    HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        this.commentsPanel.layoutComments(requestResponse.getComments());
    }

    private void init(CommentFrame commentFrame) {
        frame = new JFrame();
        frame.dispose();
        frame.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                sharedValues.getRequestCommentModel().removeCommentSession(commentFrame);
            }
        });
        JPanel topPane = new JPanel(new BorderLayout());
        JSplitPane splitter = new JSplitPane();
        splitter.setDividerLocation(450);
        splitter.setOrientation(JSplitPane.VERTICAL_SPLIT);
        JTabbedPane reqRespTabbedPane = new JTabbedPane();
        IMessageEditor requestMessageToDisplay = sharedValues.getCallbacks().createMessageEditor(
                new MessageEditorController(
                        requestResponse.getHttpService(),
                        requestResponse.getRequest(),
                        requestResponse.getResponse()),
                false);
        requestMessageToDisplay.setMessage(requestResponse.getRequest(), true);
        IMessageEditor responseMessageToDisplay = sharedValues.getCallbacks().createMessageEditor(
                new MessageEditorController(
                        requestResponse.getHttpService(),
                        requestResponse.getRequest(),
                        requestResponse.getResponse()),
                false);
        if (requestResponse.getResponse() != null) {
            responseMessageToDisplay.setMessage(requestResponse.getResponse(), true);
        } else {
            responseMessageToDisplay.setMessage(new byte[]{}, false);
        }
        reqRespTabbedPane.addTab("Request", requestMessageToDisplay.getComponent());
        reqRespTabbedPane.addTab("Response", responseMessageToDisplay.getComponent());
        splitter.setTopComponent(reqRespTabbedPane);

        commentsPanel = new CommentsPanel();
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
                        new SwingWorker<Boolean, Void>() {
                            @Override
                            public Boolean doInBackground() {
                                RequestComment newComment = new RequestComment(commentArea.getText().trim(), userWhoInitiated);
                                sharedValues.getRequestCommentModel().addCommentToNewOrExistingReqResp(newComment, requestResponse);
                                sharedValues.getClient().sendCommentMessage(sharedValues.getRequestCommentModel().findRequestResponseWithComments(requestResponse));
                                commentArea.setText("");
                                commentsPanel.addComment(newComment);
                                return Boolean.TRUE;
                            }

                            @Override
                            public void done() {
                                //we don't need to do any cleanup so this is empty
                            }
                        }.execute();
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

class JPanelListCellRenderer implements ListCellRenderer<JPanel> {

    @Override
    public Component getListCellRendererComponent(JList<? extends JPanel> list, JPanel value, int index, boolean isSelected, boolean cellHasFocus) {
        return value;
    }
}

class JPanelListModel extends AbstractListModel<CommentPanel> {
    private ArrayList<CommentPanel> panels;

    JPanelListModel() {
        panels = new ArrayList<>();
    }

    @Override
    public int getSize() {
        return panels.size();
    }

    void addPanel(CommentPanel panel) {
        this.panels.add(panel);
        fireContentsChanged(this, this.panels.size() - 1, this.panels.size() - 1);
    }

    @Override
    public CommentPanel getElementAt(int index) {
        return panels.get(index);
    }

    void addNewComments(List<RequestComment> comments) {
        this.panels.clear();
        for (RequestComment comment : comments) {
            this.panels.add(new CommentPanel(comment));

        }
        fireContentsChanged(this, 0, this.panels.size() - 1);
    }
}

class CommentsPanel extends JScrollPane {
    private JList<CommentPanel> commentsList;

    CommentsPanel() {
        commentsList = new JList<>();
        commentsList.setCellRenderer(new JPanelListCellRenderer());
        commentsList.setModel(new JPanelListModel());
        setPreferredSize(new Dimension(400, 700));
        setViewportView(commentsList);
    }

    void addComment(RequestComment comment) {

        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                ((JPanelListModel) commentsList.getModel()).addPanel(new CommentPanel(comment));
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
    }

    void layoutComments(List<RequestComment> comments) {
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                ((JPanelListModel) commentsList.getModel()).addNewComments(comments);
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
    }
}

class CommentPanel extends JPanel {

    private RequestComment comment;

    CommentPanel(RequestComment comment) {
        this.comment = comment;
        setLayout(new BorderLayout());
        setSize(new Dimension(400, 120));
        JPanel statusPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPane.add(new JLabel(comment.getUserWhoCommented() + " - " + comment.getTimeOfComment()));
        add(statusPane, BorderLayout.PAGE_START);
        add(new JLabel(comment.getComment()), BorderLayout.CENTER);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CommentPanel that = (CommentPanel) o;
        return Objects.equals(comment, that.comment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(comment);
    }
}