# BurpSuite-Team-Extension
This Burpsuite plugin allows for two testers to share live proxy requests, and reapeater/intruder payloads with each other. All requests coming through your Burp instance is shared with all other testers on the server and vice-versa! 

It uses a lightweight server built in Go that ferries the traffic back and forth. To run it, clone the server submodule then run the Dockerfile like so:
```
   docker build -t burpserver
   docker run -p 8989:8989 -t burpserver
```

Once the server is running, load the jar file into Burp through the extension menu, navigate to the new menu, input the server and port where the server is running, hit connect, and you're on your way to collaboratively web hacking!
