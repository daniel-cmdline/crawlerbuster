This script runs on server side and captures ip's who are making too many GET requests based on apache2's logs and drops all incoming packages from them using iptables (banning them).
```
-> 🕣 It monitors and parses the logs for GET requests, extracting ip's and timestamps.

-> ⚖️ Compares the timestamps for each ip and makes sure only timestamps within the window are present in the deque.

-> 🚫 If the deque surpasses the threshold and it's within window, malicious activity is found and it blocks the ip using iptables.

-> 🔍 It can also check for potential keywords like, admin.php or other critical areas and if it finds those, blocks ip immediately.

-> 🏳️ Safe Ip List enabled for skipping checks on specific Ip's

-> 🕵️ Optional feature to report the ips for blacklisting to abuseipdb.com.

-> 🔧 More features coming...
```

[OPTIONAL]
```
<<>>⚠️IP REPORTING FOR BLACKLISTING⚠️<<>>

If you want to report ips for blacklisting and contribute to the security of the web:

-> Register for an api key at https://www.abuseipdb.com/account/api

-> Insert your api-key on config.ini file.
```

If you don't have the requests module installed globally you will need to:
```
->Enter the project's folder then create virtual enviroment, activate it and install requests module then proceed with the installation
```
Most environments already have requests module installed, in case you want to check:
```
/usr/bin/python3 -c "import requests; print(requests.__file__)"
```
If you get an output like this
```
/usr/lib/python3/dist-packages/requests/__init__.py
```
You're set. 👍
If not, then do:
```
cd path/to/crawlerbuster
python -m venv venv
source venv/bin/activate
pip install requests 
```
If you don't want to report bad actors, skip all of the above and:

🛠️ Start by configuring the config.ini to Adjust Params to your liking 🛠️
```
log_path = (the path to your apache2 access.log, default value already set)
window = (window size in seconds) 
threshold = (total get requests allowed within window)
ban_duration = (logic not implemented yet)
safe_ip_list = (one big string separated by empty spaces "example1.ip.1 example2.ip.2 example3.ip.3")
keywords = (one big string separated by empty spaces "/critical /admin /someotherkeyword")
```
-> Here are some aggressive illustrative examples of time window and threshold parameters for different services, with the aim of immediately flagging or blocking unusual crawling behavior:
```
Small Personal Blog 
Window Size: 30 seconds

Threshold: 15 requests

Reasoning: A typical user isn't likely to visit more than 15 pages (or a combination of pages and assets) in 30 seconds on a personal blog. This is still generous enough for casual Browse but quickly flags automated scripts.

Medium E-commerce Site 
Window Size: 10 seconds

Threshold: 30 requests

Reasoning: E-commerce sites can be more interactive, with users clicking on products, applying filters, and loading more assets. However, 30 requests in 10 seconds is still a lot of activity for a human.

API Endpoint with Heavy Usage 
Window Size: 5 seconds

Threshold: 10 requests

Reasoning: API calls can indeed be rapid, but even for heavy usage, 10 requests per 5 seconds from a single IP is a significant sustained rate. This threshold is designed to immediately detect and mitigate "burst" attacks or rapid enumeration attempts.
```
-> Then Follow these steps to activate the service 🕷️🔫🔫🔫

1~ Create a service entry 
```
sudo nano /etc/systemd/system/crawlerbuster.service
```
2~ Paste this in the .service file you just created (DON'T FORGET TO CHANGE the Script's path, your Username and Working directory)
```
[Unit]
Description=CrawlerBuster Apache Log Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /PATH/TO/crawlerbuster.py
WorkingDirectory=/PATH/TO/crawlerbuster 
Restart=on-failure
StandardOutput=journal
StandardError=journal
User=<YOUR_USER_HERE>

[Install]
WantedBy=multi-user.target
```
3~ Add your user to be able to run iptables without password
```
sudo visudo
yourusername ALL=(ALL) NOPASSWD: /sbin/iptables
```
4~ Make sure your user is in the adm group
```
getent group adm
```
If not then add your user
```
sudo usermod -aG adm $(whoami)
```
5~ Refresh systemd and enable service
```
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable crawlerbuster.service
sudo systemctl start crawlerbuster.service
```
check service and current logging
```
systemctl status crawlerbuster.service
```

- You're Done! - 👍
Created by Daniel Cmdline -
If you have any suggestions and/or want to contribute to this project get in touch!
daniel.cmdline@humanoid.net






