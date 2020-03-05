package teamextension;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

class SharedLinksModel extends AbstractTableModel {

    private final ArrayList<SharedRequest> httpRequestResponses;
    private final SharedValues sharedValues;

    SharedLinksModel(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
        httpRequestResponses = new ArrayList<>();
    }

    void addBurpMessage(HttpRequestResponse burpMessage, String datetime) {
        httpRequestResponses.add(new SharedRequest(burpMessage, datetime));
        sharedValues.getCallbacks().printOutput("Created SharedRequestObject");
        fireTableDataChanged();
    }

    void removeBurpMessage(int rowIndex) {
        httpRequestResponses.remove(rowIndex);
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return httpRequestResponses.size();
    }

    @Override
    public String getColumnName(int col) {
        if (col == 0) {
            return "URL";
        } else {
            return "Date Created";
        }
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public Object getValueAt(int row, int col) {
        Object temp = null;
        if (col == 0) {
            temp =
                    sharedValues.getCallbacks().getHelpers().analyzeRequest(httpRequestResponses.get(row).getRequestResponse()).getUrl().toString();
        } else if (col == 1) {
            temp = httpRequestResponses.get(row).getDatetime();
        }
        return temp;
    }

    HttpRequestResponse getBurpMessageAtIndex(int rowIndex) {
        return httpRequestResponses.get(rowIndex).getRequestResponse();
    }

    void removeAllElements() {
        httpRequestResponses.clear();
    }
}
