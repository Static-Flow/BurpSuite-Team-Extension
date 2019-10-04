package teamExtension;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.EventObject;

public class CommentFrame {

    private final IHttpRequestResponse requestResponse;
    private final IBurpExtenderCallbacks callbacks;
    private final String userWhoInitiated;

    public CommentFrame(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, String userWhoInitiated) {
        this.callbacks = callbacks;
        this.requestResponse = requestResponse;
        this.userWhoInitiated = userWhoInitiated;
        initUI();
    }

    private void initUI() {
        JFrame frame = new JFrame();
        JPanel topPane = new JPanel(new BorderLayout());
        JSplitPane splitter = new JSplitPane();
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
        //topPane.add(reqRespTabbedPane,BorderLayout.PAGE_START);

        JPanel commentsViewPanel = new JPanel(new BorderLayout());
        JTable commentsTable = new JTable();
        commentsTable.setModel(new CommentModel());
        commentsTable.setDefaultEditor(RequestComment.class, new RequestCommentTableCellEditor());
        commentsTable.setDefaultRenderer(RequestComment.class, new RequestCommentTableCellEditor());
        commentsTable.setRowHeight(120);
        JScrollPane commentsScrollPane = new JScrollPane(commentsTable);
        commentsViewPanel.add(commentsScrollPane, BorderLayout.CENTER);
        splitter.setBottomComponent(commentsViewPanel);
        topPane.add(splitter, BorderLayout.CENTER);
        //topPane.add(commentsViewPanel,BorderLayout.CENTER);

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
                        RequestComment newComment = new RequestComment(commentArea.getText().trim(), userWhoInitiated);
                        commentArea.setText("");
                        ((CommentModel) commentsTable.getModel()).addComment(newComment);
                        System.out.println(commentsTable.getModel().getRowCount());
                    }
                }
            }
        });
        addCommentPanel.add(commentAreaScroller, BorderLayout.CENTER);
        topPane.add(addCommentPanel, BorderLayout.PAGE_END);

        frame.add(topPane, BorderLayout.CENTER);
        frame.pack();
        frame.setVisible(true);
    }
}

class CommentModel extends AbstractTableModel {

    private final ArrayList<RequestComment> comments;

    CommentModel() {
        comments = new ArrayList<>();
    }

    void addComment(RequestComment comment) {
        comments.add(comment);
        fireTableDataChanged();
    }

    void removeComment(int rowIndex) {
        comments.remove(rowIndex);
        fireTableDataChanged();
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return true;
    }

    @Override
    public int getRowCount() {
        return comments.size();
    }

    public String getColumnName(int col) {
        return "Comments";
    }

    @Override
    public int getColumnCount() {
        return 1;
    }

    public Class getColumnClass(int columnIndex) {
        return RequestComment.class;
    }

    @Override
    public RequestComment getValueAt(int rowIndex, int columnIndex) {
        return comments.get(rowIndex);
    }

    RequestComment getCommentAtIndex(int rowIndex) {
        return comments.get(rowIndex);
    }
}

class RequestCommentTableCellEditor extends DefaultCellEditor implements TableCellRenderer {

    private JPanel commentPanel;
    private JLabel commentHeaderLabel;
    private JTextArea commentTextArea;
    private JButton replyToCommentButton;
    private JButton deleteCommentButton;

    RequestCommentTableCellEditor() {
        super(new JCheckBox());
        commentPanel = new JPanel(new BorderLayout());
        JScrollPane commentScroller = new JScrollPane();
        JPanel headerPanel = new JPanel(new FlowLayout());
        commentHeaderLabel = new JLabel();
        commentHeaderLabel.setHorizontalAlignment(SwingConstants.LEFT);
        commentHeaderLabel.setVerticalAlignment(SwingConstants.TOP);
        headerPanel.add(commentHeaderLabel);
        replyToCommentButton = new JButton("Reply...");
        headerPanel.add(replyToCommentButton);
        deleteCommentButton = new JButton("Delete Comment");
        headerPanel.add(deleteCommentButton);
        commentTextArea = new JTextArea();
        commentTextArea.setLineWrap(true);
        commentTextArea.setEditable(false);
        commentTextArea.setWrapStyleWord(true);
        commentTextArea.setBorder(null);
        commentScroller.getViewport().add(commentTextArea);

        commentPanel.add(headerPanel, BorderLayout.PAGE_START);
        commentPanel.add(commentScroller, BorderLayout.CENTER);
    }

    @Override
    public boolean isCellEditable(EventObject anEvent) {
        return true;
    }

    public Component getTableCellEditorComponent(JTable table, Object value,
                                                 boolean isSelected, int row, int column) {
        commentTextArea.setCaretPosition(0);
        RequestComment comment = (RequestComment) value;
        commentHeaderLabel.setText("" + comment.getUserWhoCommented() + " at " + comment.getTimeOfComment());
        commentTextArea.setText(comment.getComment());
        commentTextArea.setCaretPosition(0);
        return commentPanel;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        commentTextArea.setCaretPosition(0);
        RequestComment comment = (RequestComment) value;
        commentHeaderLabel.setText("" + comment.getUserWhoCommented() + " at " + comment.getTimeOfComment());
        if (comment.getComment().length() > 497) {
            commentTextArea.setText(comment.getComment().substring(0, 497) + "...");
        } else {
            commentTextArea.setText(comment.getComment());
        }
        commentTextArea.setCaretPosition(0);
        return commentPanel;
    }
}