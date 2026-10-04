# DOTS

Blockchain:

Decentralized Open Telecommunication System

Abstract. A decentralized version of the telecom industry would allow voice, video, text communications to be sent directly from one party to another without going through a intercepted telecom networks. SIP Registrars & Presence Agent provide part of the solution, but the main benefits are lost if SIP Servers are not interconnected. We propose a solution to this problem using a the DTP network. The decentrerlized SIP registrars and SIP presence agents are replicated across the world, forming a record that cannot be changed . The longest chain not only serves as proof of the sequence of events witnessed, but proof that it came from the largest pool of SIP Servers. The network itself requires minimal structure. Messages are broadcast on a best effort basis, and SIP nodes can leave and rejoin the network at will.

1- Introduction

Mobile users has come to rely almost exclusively on intercepted telecom institutions or OTTs backed by "who knows" serving as trusted third parties to process digital communications. While the system works well enough for most transactions, it still suffers from the inherent weaknesses of the trust based model. Completely private communications are not really possible, since telecom institutions and OTT (Over the top) providers cannot avoid mediating the communications between users. The cost of mediation increases transaction costs, limiting the minimum privacy rights that users expect with their communications. the need for trust spreads. 

What is needed is an decentralized telecom platform based on distributed and replicated SIP Servers around the world to register users securely and share location/presence information with other nodes on the network and route communications between them without interfering with media flow and for text-messaging an end-to-end encryption protocol such as SIGNAL, as well an open-source clients for smartphones/desktops to consume the service, allowing any two or more willing parties to communicate directly with each other without the need for a third party.  In this paper, we propose a solution to the intercepted communications problem using a peer-to-peer distributed SIP servers to generate and replicate presence of registered users on the network and replicate it across nodes. The system is secure as long as honest nodes collectively control more CPU power than any cooperating group of attacker nodes. 



2- Network 

The steps to run the network are as follows: 

New Subscriptions are broadcasted to all SIP nodes on the network. 
 Each node collects new user registration subscription information (presence)
 When a node verifies the subscription, it broadcasts the information to all nodes. 
Nodes accept the subscription infromation only if verified that the user is online 
Nodes always consider the SIP Presence  be the correct one if it pings the users and receives a positive response and will keep working on pinging it as scheduled to ensure the status of the user. If two nodes broadcast different versions of the subscription information simultaneously, some nodes may receive one or the other first. In that case, they work on the first one they received and verifies it, but save the other one in case it becomes online. The tie will be broken when the next proof of location is found the nodes that were working on the other branch will then switch to the valid one. 

New broadcasts do not necessarily need to reach all SIP nodes. As long as they reach many nodes, they will be replicated once verified by at least one node.

Any SIP Registrar and SIP Presence agent on the internet today (estimated to be in the many thousands ) can become a node on the D.O.T.S network and accept calls FROM/TO the decentralized SIP network and get rewarded for completing/terminating calls, an open-source PBX system with 20 extensions is considered as an independent Telecom operator by D.O.T.S and should be rewarded for completing calls, a network with more sip endpoints e.g 1.5 billion endpoints by WhatsApp is also considered a Telecom operator by D.O.T.S but will be only rewarded more if it terminates more  transactions (voice, video,text) to its network of SIP endpoints. 

3- Privacy

 Media Flow & SIP Signaling:




As you can see on the right the SIP endpoint will chose the closest available node to perform the SIP registration/subscription on and when a call is initiated, routed by SIP nodes and connected (200OK) the media flow will be done directly between the sip endpoints using built-in SRTP on the SIP client software utilized by users.

The SIP signaling will happen on the decentralized SIP nodes which are interconnected and replicated across the world so it is never relaying on a single node or institution to perform the transaction, incase the SIP client fails to connect on a node it will auto-retry to the next closest one until it receives the 200OK and registers successfully.

4- SIP Clients for D.O.T.S (IOS, Android, Blackberry, Nokia, Windows, Mac, Linux)

To make a use for the decentralized network we must provide intuitive and well designed SIP clients for users on every platform, for that we can make a great use of the PJSIP project.

PJSIP is a free and open source multimedia communication library written in C language implementing standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. It combines signaling protocol (SIP) with rich multimedia framework and NAT traversal functionality into high level API that is portable and suitable for almost any type of systems ranging from desktops, embedded systems, to mobile handsets.

Why PJSIP

Complete and Integrated

PJSIP attempts to provide you, the developer, with everything you need to build real-time multimedia communication application. All three main components of real-time multimedia application, i.e. signaling, media features, and NAT traversal, have been taken care of by PJSIP. Leave those to us and you can concentrate on the application logic.

See complete list of PJSIP features in PJSIP Datasheet .

Very Portable

it will run on any flavor of Windows, Windows Mobile/CE up to WM 6, Mac OS X both PPC and Intel, Linux on any processor types, many flavor of Unix systems, Nokia/Symbian 3rd and 5th Edition devices, Apple iOS on iPhone, iPad, and iPod, BlackBerry 10, and Android (planned in v2.2). 

PJSIP has also been used in embedded systems, with people reported successful use on embedded OS/RTOS such as uC-Linux, QNX, and RTEMS across different type of processors. PJSIP runs on a 20Mhz MIPS processor appliance.

Compact, Small Footprint

A voice call application starts from as little as 150KB using the lower level libraries, or few hundred KB using the higher level PJSUA-LIB API, which take heap usage from couple of hundred KB for two calls. Footprint will of course vary with the features that are used, but hopefully this gives a broad indication.

For more information about PJSIP footprint, see the footprint discussion in our FAQ .

Opensource project using PJSIP:

https://trac.pjsip.org/repos/wiki/Projects_Using_PJSIP

5- Reward System

The main important thing that you might ask your self by now, other than privacy and decentralized communications, how will contributors from node managers to end-users get rewarded for moving to the D.O.T.S network! 

The answer is simply, we're going to utilize the well-known blockchain technology to automatically reward wallets for completing transactions, either by utilizing an existing coin (Bitcoin, Ethers, Ripple etc..) or by D.O.T.S own initial coin offering (ICO) that has its own potential.

Utilizing the proven blockchain and crypto-currency network to automate rewards (payments) for the nodes and users that complete a successful transaction counted by its duration (Call Duration) will be rewarded with X amount of coins into their wallet automatically that can  be exchanged to real money. 

Since SIP (Session Initiation Protocol) and Crypto Currency are both open-source and are programmable we can achieve this goal and automate it completely with the contribution of both SIP developers and Blockchain developers.

6- Initial resources needed to achieve this project:

Server Side SIP development contributors (Kamalio, OpenSIPs ..)
PJSIP development contributors (To develop different SIP clients across the platform)
WebRTC development contribution (Video Communications)
SIP over Websockets development contributors
Blockchain Developers
ICO (Initial Coin Offering) contributors
API development contributors (For Lookups and integration with rest of the world)


Conclusion:

Users will be able to commnicate privately and securely with each other around the world utilizing the decentralized network, enjoy more uptime and better service.

Users can always keep the same phone number and use it across all networks in the world.

Node managers will get rewarded for transactions/traffic completed through their nodes.

Users can finally get paid and rewarded for communicating instead of paying, the wealth that centralized telecom operators make will be spread around the world.

Existing service providers can enroll their existing network as a node and bridge the D.O.T.S user base to the PSTN network and get rewarded for completing transactions, as well focus on the important task like creating better connectivity and expand their networks to handle more data through their infrastructure.







