package teamextension;

import javax.swing.*;
import java.awt.*;

class ServerListModel extends DefaultListModel<Room> {

    ServerListModel() {
    }

    @Override
    public void addElement(Room element) {
        super.addElement(element);
    }

    @Override
    public void removeAllElements() {
        super.removeAllElements();
    }

    @Override
    public Room getElementAt(int index) {
        return super.getElementAt(index);
    }

}

class ServerListCustomCellRenderer implements ListCellRenderer<Room> {

    @Override
    public Component getListCellRendererComponent(JList<? extends Room> list, Room room, int index, boolean isSelected, boolean cellHasFocus) {
        return new JLabel(room.getRoomName());
    }
}