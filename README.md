# BurpSuite-Team-Extension

This Burpsuite plugin allows for multiple testers to share live/historical proxy requests, scope and reapeater/intruder payloads with each other in real time allowing for truely collaborative web app testing. When connected to the Team Sever and in a Team Room all requests coming through your Burp client are shared with the other testers in the room and vice-versa!

# Features

 + Real time request/response pairs shared between all clients
 
 + AES Encryption of all traffic between client and server
 
 + Seperate Team Rooms to allow multiple teams on 1 server
 
 + Mute individual team members or whole room
 
 + Pause sending traffic to room
 
 + Sync scope between all clients in a room
 
 + Share Repeater/Intruder payloads with individual team members or whole room 
 
 + Share specific request/response pairs with individual team members or whole room 

 + More to come!
 
# How it works

There are two parts that make this collaborative web app testing possible. 1st is obviously a Burpsuite Plugin that uses the APIs to capture request/response pairs and ferry them to the server and receive other clients traffic. It is the main UI that users see when using this tool. 2nd is a lightweight server written in GO which manages the connections between the clients and the rooms.

# How to start the Server

```
git clone https://github.com/Static-Flow/BurpSuite-Team-Extension.git
cd BurpSuite-Team-Extension
git submodule update --init --recursive
cd BurpSuiteTeamServer/cmd/BurpSuiteTeamServer
go build
./BurpSuiteTeamServer
```
Output:
```
This is the server key that clients need to login: <Server key>
Starting chat room server
Awaiting Clients...
```

# How to install the Burpsuite plugin

The jar file is prebuilt for you within the build/jar folder. To use the prebuilt jar:
 1. Start Burpsuite 
 2. Navigate to the Extender tab
 3. Click add and select the jar file from the git repository
 4. New Burpsuite tab titled "Burp TC" should appear
 
# How to use Burp Team Server Features
 ## Server Actions 
  These actions can be taken by a client that has connected to a server
  
  #### Connect to server
  1. Navigate to the "Burp TC" tab
  2. Enter a chosen username, the server IP address, port and password
  3. Click the "Connect" button

  #### Disconnect from server
  1. Click the "Disconnect" button

  #### Create a new room
  1. Click the "New Room" button
  2. Enter a room name
  3. Click "Ok"

  #### Join a room
  1. The bottom right panel will show current server rooms or "No rooms currently" if none exist
  2. Right click on the desired room and click "Join"
  
 ## Room Actions
  These actions can be taken by a client that has connected to a server and joined a room
  
  #### Leave a room
  1. Click the "Leave Room" button

  #### Pause sending data to server
  1. Click the "Pause" button

  #### Unpause sending data to server
  1. Click the "Unpause" button

  #### Mute individual team member
  1. The bottom right panel will show current room members
  2. Right click on the desired room and click "Mute"
  
  #### Unmute individual team member
  1. The bottom right panel will show current room members
  2. Right click on the desired room and click "Unmute"
 
  #### Mute all team members
  1. Click the "Mute All" button
  
  #### Set room scope
  (This can only be done by the client that starts the room)
  1. Use the Target tab to set the Burpsuite scope as desired
  2. Within the "Burp TC" tab click the "Set Room Scope" button
  
  #### Get room scope
  2. Click the "Get Room Scope" button
 ## Room Actions
  These actions apply to Burpsuite tools outside of the "Burp TC" tab
  
  #### Share a Repeater payload with whole Team
  1. Within the Repeater tab right click within the Request editor and mouse over "Share Repeater Payload"
  2. Select "To Group"
  
  #### Share a Repeater payload with Team member
  1. Within the Repeater tab right click within the Request editor and mouse over "Share Repeater Payload"
  2. Mouse over "To Teammate"
  3. Select the name of the desired team member
  
  #### Share an Intruder payload with whole Team
  1. Within the Intruder tap navigate to the "Positions" tab
  2. Within the "Positions" tab right click within the Request editor and mouse over "Share Intruder Payload"
  3. Select "To Group"
  
  #### Share an Intruder payload with Team member
  1. Within the Intruder tap navigate to the "Positions" tab
  2. Within the "Positions" tab right click within the Request editor and mouse over "Share Intruder Payload"
  3. Mouse over "To Teammate"
  4. Select the name of the desired team member
  
  #### Share a Proxy Request with whole Team
  1. Within the Target tap navigate to the "Site map" tab
  2. Within the "Site map" tab right click on the entry you would like to share and mouse over "Share Request"
  3. Select "To Group"
  
  #### Share a Proxy Request with Team member
  1. Within the Target tap navigate to the "Site map" tab
  2. Within the "Site map" tab right click on the entry you would like to share and mouse over "Share Request"
  3. Mouse over "To Teammate"
  4. Select the name of the desired team member
