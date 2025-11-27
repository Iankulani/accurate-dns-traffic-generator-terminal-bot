# accurate-dns-traffic-generator-terminal-bot
The Accurate-DNS-Traffic-Generator-Terminal-Bot is a robust and highly configurable cybersecurity utility designed to simulate realistic DNS traffic directly from a terminal or command-line interface.

Built for penetration testers, cyber defense engineers, and network researchers, this tool empowers users to generate customizable DNS request streams that mimic legitimate and adversarial behavior.

The primary goal of this bot is to assist with testing DNS-based threat detection systems, intrusion prevention mechanisms, firewall behavior, and DNS filtering policies under varied traffic loads and patterns. 

Users can control the frequency, domain pattern, record type (A, AAAA, TXT, MX, etc.), and packet payload characteristics to fine-tune the generation of DNS traffic. 

Whether you need to stress-test DNS servers or analyze resolver response latency, this tool provides reliable and repeatable performance.

One of the standout features of the tool is its Telegram integration. Users can configure the bot to connect with a Telegram account using a Bot Token and Chat ID, allowing real-time monitoring, control, and alerts directly through Telegram messages. This includes updates on the traffic generation process, DNS response metrics, success/failure logs, and any anomalies detected during traffic execution. This capability makes remote monitoring and team collaboration seamless, especially in distributed test environments.

The bot is fully terminal-based, which ensures high compatibility with Linux, macOS, and Windows through WSL or native command lines. 
It’s lightweight, portable, and requires minimal dependencies to run. All configurations can be handled via a user-friendly .env file or direct command-line flags. 
The DNS traffic patterns can be randomized or fixed, allowing flexibility for stealth mode simulations or predictable load testing.

## How to Install
```bash
git clone https://github.com/Iankulani/accurate-dns-traffic-generator-terminal-bot.git

cd accurate-dns-traffic-generator-terminal-bot
```

## How to run
```bash

python3 accurate-dns-traffic-generator-terminal-bot.py  
```
