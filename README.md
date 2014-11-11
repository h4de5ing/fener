-http://www.freebuf.com/tools/50734.html
-自动化渗透测试工具 – Heybe
-Fener，优化过的主机快速发现工具。Fener利用多种网络工具，来发现目标网络中的所有主机。
FENER - Automated Information Gathering Tool for Penetration Testers 
=====


![](https://github.com/galkan/fener/blob/master/images/fener_desc3.png "Fener")  


Fener (flashlight) is automated info gathering tool that can be used by penetration testers. Main purpose is to automate and speed up network discovery, port scanning and info gathering phase.
Fener gathers information with 3 different methods:

- Active scan  
This method uses nmap in background to actively discover host in target network. Different nmap scan techniques are preconfigured and used in automated way. All scan resuls are saved in 3 different nmap report formats for later inspection. 
- Passive scan  
This method is used for stealty network discovery. No packet is send during this scan. Only network traffic is sniffed and analyzed to discover assets. This methos optionally can use arpsoof to perform man-in-the-middle and listen all network traffic. 
- Screenshot scan   
This method is used to quickly discover web applications in target network. Quick port scan is performed to discover open web ports and then screenshots of discovered web pages is taken and saved in output directory. With this method all web pakes in target network can be archived and examined offline. 

**Common features**
- Multi threaded 
- Database support
- Written in Python
- Custom reporting
- Logging 


###Prerequisities
- Python 2.7+ 
- Nmap
- PhantomJS
- Wireshark/Tshark
- Tcpdump
- Arpsooof/Ettercap
- SQLite


###Installation
..
''
`` 
git clone https://github.com/galkan/fener/
`` 
###Usage



###Examples 

./fener -a 

###Log Format
>>>>>>> origin/master
