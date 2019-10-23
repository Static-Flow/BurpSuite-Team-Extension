package teamextension;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collections;

public class RoomMembersListModel extends DefaultListModel<String> {

    RoomMembersListModel() {
    }

    @Override
    public void removeAllElements() {
        super.removeAllElements();
    }


    @Override
    public String getElementAt(int index) {
        return super.getElementAt(index);
    }

    ArrayList<String> getRoomMembers() {
        return Collections.list(this.elements());
    }


}
