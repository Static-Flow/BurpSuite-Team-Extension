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
