package teamextension;

class Room {

    private boolean hasPassword;
    private String roomName;

    Room(String roomName, boolean hasPassword) {
        this.roomName = roomName;
        this.hasPassword = hasPassword;
    }

    boolean hasPassword() {
        return hasPassword;
    }

    public void setHasPassword(boolean hasPassword) {
        this.hasPassword = hasPassword;
    }

    String getRoomName() {
        return roomName;
    }

    public void setRoomName(String roomName) {
        this.roomName = roomName;
    }

    @Override
    public String toString() {
        return roomName;
    }
}
