package teamextension;

import burp.IMessageEditor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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

    HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        this.commentsPanel.layoutComments(requestResponse.getComments());
    }

    void close() {
        sharedValues.getRequestCommentModel().removeCommentSession(this);
        frame.dispose();
    }


    private void init(CommentFrame commentFrame) {
        frame = new JFrame();
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
        sharedValues.getCallbacks().printOutput(requestResponse.toString());
        IMessageEditor requestMessageToDisplay = sharedValues.getCallbacks().createMessageEditor(
                new MessageEditorController(
                        requestResponse.getHttpService(),
                        requestResponse.getRequest(),
                        requestResponse.getResponse()),
                false);
        requestMessageToDisplay.setMessage(requestResponse.getRequest(),
                true);
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
        reqRespTabbedPane.addTab("Request",
                requestMessageToDisplay.getComponent());
        reqRespTabbedPane.addTab("Response",
                responseMessageToDisplay.getComponent());
        splitter.setTopComponent(reqRespTabbedPane);
        sharedValues.getCallbacks().printOutput("Initialized request and " +
                "response");
        commentsPanel = new CommentsPanel(this.requestResponse,
                this.sharedValues);
        sharedValues.getCallbacks().printOutput("Created comment panel");
        if (!requestResponse.getComments().isEmpty()) {
            commentsPanel.layoutComments(requestResponse.getComments());
        }
        sharedValues.getCallbacks().printOutput("added new comments");
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
                                RequestComment newComment =
                                        new RequestComment(commentArea.getText().trim(), userWhoInitiated, new Date());
                                sharedValues.getRequestCommentModel().addCommentToNewOrExistingReqResp(newComment, requestResponse);
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

class JPanelListModel extends AbstractListModel<RequestComment> {
    private ArrayList<RequestComment> panels;

    JPanelListModel() {
        panels = new ArrayList<>();
    }

    @Override
    public int getSize() {
        return panels.size();
    }

    void removeComment(int index) {
        this.panels.remove(index);
        fireContentsChanged(this, 0, this.panels.size());
    }

    void addPanel(RequestComment panel) {
        this.panels.add(panel);
        fireContentsChanged(this, 0, this.panels.size());
    }

    @Override
    public RequestComment getElementAt(int index) {
        return panels.get(index);
    }

    void addNewComments(List<RequestComment> comments) throws ParseException {
        this.panels.clear();
        SimpleDateFormat format = new SimpleDateFormat("MMM dd HH:mm:ss");
        for(RequestComment requestComment : comments) {
            this.panels.add(new RequestComment(requestComment.getComment(),
                    requestComment.getUserWhoCommented(),
                    format.parse(requestComment.getTimeOfComment())));
        }
        fireContentsChanged(this, 0, this.panels.size());
    }
}

class CommentsPanel extends JScrollPane {
    private JList<RequestComment> commentsList;
    private SharedValues sharedValues;
    CommentsPanel(HttpRequestResponse requestResponse, SharedValues sharedValues) {
        this.sharedValues = sharedValues;
        commentsList = new JList<>();
        commentsList.setCellRenderer(new JPanelListCellRenderer());
        commentsList.setModel(new JPanelListModel());
        commentsList.addMouseListener( new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                /*
                Checks to see if it is a right click and if the click point is
                within the bounds of a Comments borders
                 */
                if ( SwingUtilities.isRightMouseButton(e) && commentsList.getCellBounds(commentsList.locationToIndex(e.getPoint()),commentsList.locationToIndex(e.getPoint())).contains(e.getPoint())) {
                    int selectedIndex =
                            commentsList.locationToIndex(e.getPoint());
                    RequestComment selectedComment =
                            commentsList.getModel().getElementAt(selectedIndex);
                    if (sharedValues.getClient().getUsername().equals(selectedComment.getUserWhoCommented())) {
                        JPopupMenu menu = new JPopupMenu();
                        JMenuItem itemRemove = new JMenuItem("Delete");
                        itemRemove.addActionListener(e1 -> {
                            sharedValues.getCallbacks().printOutput(
                                    "Deleting comment " + selectedComment);
                            ((JPanelListModel) commentsList.getModel()).removeComment(selectedIndex);
                            sharedValues.getRequestCommentModel().removeCommentFromNewOrExistingReqResp(selectedComment, requestResponse);
                        });
                        menu.add(itemRemove);
                        menu.show(commentsList, e.getPoint().x, e.getPoint().y);
                    }
                }
            }
        });
        setPreferredSize(new Dimension(400, 700));
        setViewportView(commentsList);
    }

    void addComment(RequestComment comment) {

        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                ((JPanelListModel) commentsList.getModel()).addPanel(comment);
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
                try {
                    ((JPanelListModel) commentsList.getModel()).addNewComments(comments);
                } catch (ParseException e) {
                    sharedValues.getCallbacks().printError(e.getMessage());
                }
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //we don't need to do any cleanup so this is empty
            }
        }.execute();
    }
}