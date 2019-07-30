package teamExtension;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;

class ServerWriteThread implements Runnable {

    private BlockingQueue<String> messageQueue;
    private PrintWriter streamOut = null;
    private boolean exit;

    ServerWriteThread(Socket serverSocket, BlockingQueue<String> messageQueue) {
        this.exit = false;
        try {
            this.messageQueue = messageQueue;
            this.streamOut = new PrintWriter(serverSocket.getOutputStream(), true);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    void stop() {
        exit = true;
    }

    @Override
    public void run() {
        while (!exit) {
            if (!this.messageQueue.isEmpty()) {
                try {
                    String message = this.messageQueue.take();
                    System.out.println("Inside messg count: " + this.messageQueue.size());
                    this.streamOut.println(message);
                    this.streamOut.flush();
                    if (message.equalsIgnoreCase("bye")) break;
                } catch (Exception exception) {
                    System.out.println(exception.getMessage());
                }
            }
        }
    }
}
