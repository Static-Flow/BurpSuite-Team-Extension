# BurpSuite-Team-Extension

This Burpsuite plugin allows for multiple testers to share live/historical proxy requests, scope and repeater/intruder payloads with each other in real time allowing for truly collaborative web app testing. When connected to the Team Sever and in a Team Room all requests coming through your Burp client are shared with the other testers in the room and vice-versa!

## Request from clients to target propegated to other clients
![Image of Request being made](https://github.com/AonCyberLabs/BurpSuite-Team-Extension/blob/master/images/request.png)

## Response from target to clients propegated to other clients
![Image of Request being made](https://github.com/AonCyberLabs/BurpSuite-Team-Extension/blob/master/images/response.png)

# Features

 + Real time request/response pairs shared between all clients
 
 + Mutual TLS Encryption of all traffic between client and server
 
 + Seperate Team Rooms to allow multiple teams on 1 server
 
 + Mute individual team members or whole room
 
 + Pause sending traffic to room
 
 + Sync scope between all clients in a room
 
 + Share Repeater/Intruder payloads with individual team members or whole room 
 
 + Share specific request/response pairs with individual team members or whole room 

 + Generate shareable links to Burp Suite Requests that can be shared outside of Burp Suite
 
 + Add comments to Burp Suite requests that are v iewable by other teammates
 
 + Automatic sharing of discovered Cookies
 
 + Automatic sharing of discovered Passive/Active scan findings
 
 + Configure sharing of all requests or just in scope ones
 
 + Configure sharing/receiving Cookies
 
 + Configure sharing/receiving Issues
 
 + Save connection settings
 
# How it works

There are two parts that make this collaborative web app testing possible. 1st is obviously a Burpsuite Plugin that uses the APIs to capture request/response pairs and ferry them to the server and receive other clients traffic. It is the main UI that users see when using this tool. 2nd is a lightweight server written in GO which manages the connections between the clients and the rooms.

# How to start the Server

```
go get github.com/AonCyberLabs/BurpSuiteTeamServer/cmd/BurpSuiteTeamServer
cd ~/go/src/github.com/AonCyberLabs/BurpSuiteTeamServer/
go get ./...
go install ./...
~/go/bin/BurpSuiteTeamServer -h
```
Output:
```
Usage of BurpSuiteTeamServer:
  -host string
    	host for TLS cert. Defaults to localhost (default "localhost")
  -port string
    	http service address (default "9999")
  -serverPassword string
    	password for the server
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
  2. Enter a chosen username, the server IP address, port and server password (if required)
  3. Navigate to the "Configuration" tab within the "Burp TC" tab
  4. Using the "Select Certificate" file selection button, pick the server certificate generated when the server started
  5. Using the "Select Certificate Key" file selection button, pick the server certificate key generated when the server started
  6. Click the "Connect" button

  #### Disconnect from server
  1. Click the "Disconnect" button

  #### Create a new room
  1. Click the "New Room" button
  2. Enter a room name
  3. If desired, enter a room password
  4. Click "Ok"

  #### Join a room
  1. The middle right panel will show current server rooms or "No rooms currently" if none exist
  2. Right click on the desired room and click "Join"
  3. If a password is required a prompt will show, enter the room password
  
 ## Room Actions
  These actions can be taken by a client that has connected to a server and joined a room
  
  #### Leave a room
  1. Click the "Leave Room" button

  #### Pause sending data to server
  1. Click the "Pause" button

  #### Unpause sending data to server
  1. Click the "Unpause" button

  #### Mute individual team member
  1. The middle right panel will show current room members
  2. Right click on the desired room and click "Mute"
  
  #### Unmute individual team member
  1. The middle right panel will show current room members
  2. Right click on the desired room and click "Unmute"
 
  #### Mute all team members
  1. Click the "Mute All" button
  
  #### Unmute all team members
  1. Click the "Unmute All" button
  
  #### Set room scope
  (This can only be done by the client that starts the room)
  1. Use the Target tab to set the Burpsuite scope as desired
  2. Within the "Burp TC" tab click the "Set Room Scope" button
  
  #### Get room scope
  2. Click the "Get Room Scope" button
  
 ## Tool Actions
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

## Custom Actions
  #### Generate shareable links as a URL
  1. Right click inside a repeater tab and select "create link"
  2. Navigate to the "Shared Links" tab within the "Burp TC" extension tab
  3. Right click on the link you would like to share and select "Get link"
  
  #### Generate shareable links as a HTML link
  1. Right click inside a repeater tab and select "create Link"
  2. Navigate to the "Shared Links" tab within the "Burp TC" extension tab
  3. Right click on the link you would like to share and select "Get HTML Link"
  
  #### Remove generated link
  1. Right click inside a repeater tab and select "create link"
  2. Navigate to the "Shared Links" tab within the "Burp TC" extension tab
  3. Right click on the link you would like to share and select "Remove link"
  
  #### Start commenting on request
  1. Right click on a Proxy history line or a request inside the Site Map
  2. Select "Comments"
  3. The comment UI will appear, enter your comment in the bottom textfield and hit enter
  
  #### View comments on request
  1. Navigate to the "Comments" tab within the "Burp TC" extension tab
  2. Double click on any threads listed in the list of comments to open the Comment UI and begin commenting
  
  #### Set server certificate
  1. Navigate to the "Configuration" tab within the "Burp TC" extension tab
  2. Click the "Select Cetificate" button
  3. Using the file picker, select the "BurpServer.pem" file generated by the server
  
  #### Set server certificate key
  1. Navigate to the "Configuration" tab within the "Burp TC" extension tab
  2. Click the "Select Cetificate Key" button
  3. Using the file picker, select the "BurpServer.key" file generated by the server
  
  #### Configure sharing only in-scope requests
  1. Navigate to the "Configuration" tab within the "Burp TC" extension tab
  2. Uncheck the "Share all requests" check-box
  
  #### Configure sending discovered issues
  1. Navigate to the "Configuration" tab within the "Burp TC" extension tab
  2. Uncheck the "Share issues" check-box
  
  #### Configure sending discovered cookies
  1. Navigate to the "Configuration" tab within the "Burp TC" extension tab
  2. Uncheck the "Share cookies" check-box
  
  #### Configure receiving discovered issues
  1. Navigate to the "Configuration" tab within the "Burp TC" extension tab
  2. Uncheck the "Receive shared issues" check-box
  
  #### Configure receiving discovered cookies
  1. Navigate to the "Configuration" tab within the "Burp TC" extension tab
  2. Uncheck the "Receive shared cookies" check-box