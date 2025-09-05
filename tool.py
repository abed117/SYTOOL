from colorama import init, Fore, Style
import os
import subprocess
import platform
import ipaddress
import time
import socket
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import requests
from bs4 import BeautifulSoup
import urllib.parse
import hashlib


init()  # Wichtig für Windows




print("""
  █████████  █████ █████ ███████████    ███████       ███████    █████      
 ███░░░░░███░░███ ░░███ ░█░░░███░░░█  ███░░░░░███   ███░░░░░███ ░░███       
░███    ░░░  ░░███ ███  ░   ░███  ░  ███     ░░███ ███     ░░███ ░███       
░░█████████   ░░█████       ░███    ░███      ░███░███      ░███ ░███       
 ░░░░░░░░███   ░░███        ░███    ░███      ░███░███      ░███ ░███       
 ███    ░███    ░███        ░███    ░░███     ███ ░░███     ███  ░███      █
░░█████████     █████       █████    ░░░███████░   ░░░███████░   ███████████
 ░░░░░░░░░     ░░░░░       ░░░░░       ░░░░░░░       ░░░░░░░    ░░░░░░░░░░░ 
                                                                            
                                                                            
                                                                            """)
print("                     made by Glitch     Version 1.0")
print("I am going to update the tool soon please check my github if there are any updates")

print("____________________________________________________________________________________________")
print('')

print("\033[31m 1) Information Gathering\033[0m")
print("\033[31m 2) Hash Cracking\033[0m")
print("\033[31m 3) Password Hashing\033[0m")

print("")

print("\033[31m 99) Exit\033[0m")
print("")

choice = int(input("\033[31m Enter number: \033[0m"))

if choice == 1:
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("""
     █████ ██████   █████ ███████████    ███████         █████████    █████████   ███████████ █████   █████             
     ▒███  ▒███▒███ ▒███  ▒███   █ ▒  ███     ▒▒███    ███     ▒▒▒  ▒███    ▒███ ▒   ▒███  ▒  ▒███    ▒███          
     ▒███  ▒███▒▒███▒███  ▒███████   ▒███      ▒███   ▒███          ▒███████████     ▒███     ▒███████████          
     ▒███  ▒███ ▒▒██████  ▒███▒▒▒█   ▒███      ▒███   ▒███    █████ ▒███▒▒▒▒▒███     ▒███     ▒███▒▒▒▒▒███          
     ▒███  ▒███  ▒▒█████  ▒███  ▒    ▒▒███     ███    ▒▒███  ▒▒███  ▒███    ▒███     ▒███     ▒███    ▒███          
     █████ █████  ▒▒█████ █████       ▒▒▒███████▒      ▒▒█████████  █████   █████    █████    █████   █████ ██ ██ ██
    ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒ ▒▒▒▒▒          ▒▒▒▒▒▒▒         ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒ ▒▒ ▒▒ ▒▒ 
                                                                                                                    
                                                                                                                    
                                                                                                                    """)
    print("_________________________________________________________________________________________________")
    print("")

    print("\033[31m 1) Ping scan\033[0m")
    print("\033[31m 2) Port Scan\033[0m")
    print("\033[31m 3) DNS Lookup\033[0m")
    print("\033[31m 4) Whois lookup\033[0m")
    print("\033[31m 5) Google Dorking\033[0m")
    print('')

    choice2 = int(input("\033[31m Enter number: \033[0m"))
    # Ping scan
    if choice2 == 1:
        os.system('cls' if os.name == 'nt' else 'clear')
        def ping_host(ip):
          param = "-n" if platform.system().lower() == "windows" else "-c"
          try:
            result = subprocess.run(
            ["ping", param, "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
            return result.returncode == 0
          except Exception as e:
            print(f"Fehler bei {ip}: {e}")
            return False

        def main():
          user_input = input("Enter the IP adress (ex: 192.168.1.1 oder 192.168.0/24): ")

          try:
            net = ipaddress.ip_network(user_input, strict=False)
          except ValueError:
            print("Ungültige Eingabe.")
            return

          print(f"\n🔍 Starte Ping-Scan auf: {net}\n")

          for ip in net.hosts():
            if ping_host(ip):
              print(f"[+] {ip} ist erreichbar")
            else:
              print(f"[-] {ip} nicht erreichbar")

        if __name__ == "__main__":
          main()
    # Port scans
    elif choice2 == 2:
      os.system('cls' if os.name == 'nt' else 'clear')
      def scan_port(ip, port, timeout=0.5):
        try:
          with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
        except:
          pass
          return None

      def main():
        target_ip = input("🎯 Ziel-IP eingeben: ").strip()
        print(f"\n🚀 Starte TCP Full Port Scan auf {target_ip} (0–65535)...\n")

        open_ports = []

        with ThreadPoolExecutor(max_workers=200) as executor:
          futures = [executor.submit(scan_port, target_ip, port) for port in range(0, 65536)]
          for future in futures:
              port = future.result()
              if port is not None:
                print(f"[+] Port {port} ist offen")
                open_ports.append(port)

        if not open_ports:
          print("\n🔒 Keine offenen Ports gefunden.")
        else:
          print(f"\n✅ Offene Ports: {open_ports}")

      if __name__ == "__main__":
        main()
        #DNS Lookup
    elif choice2 == 3:
        os.system('cls' if os.name == 'nt' else 'clear')
        def real_dns_lookup(domain):
          record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']

          print(f"\n🔍 Performing DNS lookup for: {domain}\n")

          for rtype in record_types:
            try:
              answers = dns.resolver.resolve(domain, rtype)
              print(f"🔹 {rtype} records:")
              for rdata in answers:
                print(f"   {rdata.to_text()}")
            except dns.resolver.NoAnswer:
              print(f"⚠️  No {rtype} records found.")
            except dns.resolver.NXDOMAIN:
              print("❌ Domain does not exist.")
              break
            except Exception as e:
              print(f"⚠️  Error while querying {rtype}: {e}")

        def main():
          domain = input("🌐 Enter a domain name: ").strip()
          real_dns_lookup(domain)

        if __name__ == "__main__":
          main()
    # Whois lookup
    elif choice2 == 4:
      os.system('cls' if os.name == 'nt' else 'clear')
      def whois_query(domain, server="whois.iana.org"):
        try:
       
          with socket.create_connection((server, 43), timeout=10) as sock:
            sock.sendall((domain + "\r\n").encode())
            response = sock.recv(4096).decode(errors='ignore')

        
          for line in response.splitlines():
            if line.lower().startswith("refer:"):
                real_server = line.split(":")[1].strip()
                break
          else:
            print("❌ Could not find the responsible WHOIS server.")
            return

        
          with socket.create_connection((real_server, 43), timeout=10) as sock:
            sock.sendall((domain + "\r\n").encode())
            result = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                result += data

          print(f"\n📄 WHOIS result for {domain} from {real_server}:\n")
          print(result.decode(errors='ignore'))

        except Exception as e:
          print(f"❌ Error during WHOIS lookup: {e}")

      def main():
        domain = input("🌐 Enter a domain (e.g. example.com): ").strip()
        whois_query(domain)

      if __name__ == "__main__":
        main()
    #Google dorking
    elif choice2 == 5:
      os.system('cls' if os.name == 'nt' else 'clear')
      dorks = [
    "filetype:pdf confidential",
    'intitle:"index of"',
    "inurl:admin login",
    "filetype:bak OR filetype:old OR filetype:backup",
    "filetype:key OR filetype:pem OR filetype:crt",
    'intext:"SQL syntax near"',
    'intext:"192.168." OR intext:"10."',
    "filetype:log inurl:wp-content"
]

      headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/115.0.0.0 Safari/537.36"
}

      def google_search(query, num_results=5):
        query_encoded = urllib.parse.quote_plus(query)
        url = f"https://www.google.com/search?q={query_encoded}&num={num_results}"

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
          print(f"Error: HTTP {response.status_code}")
          return []

        soup = BeautifulSoup(response.text, "html.parser")
        results = []

        for g in soup.find_all('div', class_='tF2Cxc'):
          link = g.find('a', href=True)
          title = g.find('h3')
          if link and title:
            results.append((title.text, link['href']))

        return results

      def main():
        for dork in dorks:
          print(f"\n🔍 Searching Google for: {dork}\n{'-'*50}")
          results = google_search(dork)
          if results:
            for i, (title, link) in enumerate(results, 1):
                print(f"{i}. {title}\n   {link}")
          else:
            print("No results or blocked by Google.")

        
          time.sleep(5)

      if __name__ == "__main__":
        main()
    
    # Hash cracking
elif choice == 2:
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""
 █████   █████   █████████    █████████  █████   █████      █████████  ███████████     █████████     █████████  █████   ████
▒▒███   ▒▒███   ███▒▒▒▒▒███  ███▒▒▒▒▒███▒▒███   ▒▒███      ███▒▒▒▒▒███▒▒███▒▒▒▒▒███   ███▒▒▒▒▒███   ███▒▒▒▒▒███▒▒███   ███▒ 
 ▒███    ▒███  ▒███    ▒███ ▒███    ▒▒▒  ▒███    ▒███     ███     ▒▒▒  ▒███    ▒███  ▒███    ▒███  ███     ▒▒▒  ▒███  ███   
 ▒███████████  ▒███████████ ▒▒█████████  ▒███████████    ▒███          ▒██████████   ▒███████████ ▒███          ▒███████    
 ▒███▒▒▒▒▒███  ▒███▒▒▒▒▒███  ▒▒▒▒▒▒▒▒███ ▒███▒▒▒▒▒███    ▒███          ▒███▒▒▒▒▒███  ▒███▒▒▒▒▒███ ▒███          ▒███▒▒███   
 ▒███    ▒███  ▒███    ▒███  ███    ▒███ ▒███    ▒███    ▒▒███     ███ ▒███    ▒███  ▒███    ▒███ ▒▒███     ███ ▒███ ▒▒███  
 █████   █████ █████   █████▒▒█████████  █████   █████    ▒▒█████████  █████   █████ █████   █████ ▒▒█████████  █████ ▒▒████
▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒      ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒ 
                                                                                                                            
                                                                                                                            
                                                                                                                            """)
    print("_________________________________________________________________________________________________")
    print("")

    print("\033[31m 1) Crack SHA256 hash \033[0m")
    print("\033[31m 2) Crack MD5 hash \033[0m")
    print("\033[31m 3) Crack SHA-1 hash \033[0m")
    print("")

    choice3 = int(input("\033[31m Enter number: \033[0m"))
#SHA256 cracker
    if choice3 == 1:
        os.system('cls' if os.name == 'nt' else 'clear')
        def crack_sha256(target_hash):
          wordlist_file = "list.txt"  # ← fest definierte Datei

          try:
            with open(wordlist_file, "r", encoding="utf-8") as file:
              for line in file:
                word = line.strip()
                word_hash = hashlib.sha256(word.encode()).hexdigest()

                if word_hash == target_hash:
                    print(f"\n✅ Hash cracked! The original word is: {word}")
                    return
            print("\n❌ Hash not found in the wordlist.")
          except FileNotFoundError:
            print(f"\n[!] Wordlist file '{wordlist_file}' not found.")

        if __name__ == "__main__":
          hash_input = input("🔐 Enter the SHA256 hash to crack: ").strip()
          crack_sha256(hash_input)

#MD5 cracker
    elif choice3 == 2:
      os.system('cls' if os.name == 'nt' else 'clear')
      def crack_md5(hash_to_crack, wordlist_file):
        with open(wordlist_file, "r", encoding="utf-8") as file:
          for line in file:
            password = line.strip()
            hashed_pass = hashlib.md5(password.encode()).hexdigest()
            if hashed_pass == hash_to_crack:
                return password
        return None

      def main():
        hash_to_crack = input("Enter the MD5 hash to crack: ").strip()
        wordlist_file = "list.txt"  # Hier den Pfad zu deiner Wordlist anpassen

        result = crack_md5(hash_to_crack, wordlist_file)
        if result:
         print(f"Password found: {result}")
        else:
          print("Password not found in the wordlist.")

      if __name__ == "__main__":
        main()

#SHA-1 cracker
    elif choice3 == 3:
      os.system('cls' if os.name == 'nt' else 'clear')
      def crack_sha1(hash_to_crack, wordlist_file):
        with open(wordlist_file, "r", encoding="utf-8") as file:
          for line in file:
            password = line.strip()
            hashed_pass = hashlib.sha1(password.encode()).hexdigest()
            if hashed_pass == hash_to_crack:
                return password
        return None

      def main():
        hash_to_crack = input("Enter the SHA-1 hash to crack: ").strip()
        wordlist_file = "list.txt"  # 

        result = crack_sha1(hash_to_crack, wordlist_file)
        if result:
          print(f"[✓] Password found: {result}")
        else:
          print("[✗] Password not found in the wordlist.")

      if __name__ == "__main__":
        main()

# Hash generation
elif choice == 3:
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""
 █████   █████   █████████    █████████  █████   █████      █████████  ██████████ ██████   █████
▒▒███   ▒▒███   ███▒▒▒▒▒███  ███▒▒▒▒▒███▒▒███   ▒▒███      ███▒▒▒▒▒███▒▒███▒▒▒▒▒█▒▒██████ ▒▒███ 
 ▒███    ▒███  ▒███    ▒███ ▒███    ▒▒▒  ▒███    ▒███     ███     ▒▒▒  ▒███  █ ▒  ▒███▒███ ▒███ 
 ▒███████████  ▒███████████ ▒▒█████████  ▒███████████    ▒███          ▒██████    ▒███▒▒███▒███ 
 ▒███▒▒▒▒▒███  ▒███▒▒▒▒▒███  ▒▒▒▒▒▒▒▒███ ▒███▒▒▒▒▒███    ▒███    █████ ▒███▒▒█    ▒███ ▒▒██████ 
 ▒███    ▒███  ▒███    ▒███  ███    ▒███ ▒███    ▒███    ▒▒███  ▒▒███  ▒███ ▒   █ ▒███  ▒▒█████ 
 █████   █████ █████   █████▒▒█████████  █████   █████    ▒▒█████████  ██████████ █████  ▒▒█████
▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒      ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒ 
                                                                                                
                                                                                                
                                                                                                """)
    print("_________________________________________________________________________________________________")
    print("")

    print("\033[31m 1) Create SHA256 hash \033[0m")
    print("\033[31m 2) Create MD5 hash \033[0m")
    print("\033[31m 3) Create SHA-1 hash \033[0m")
    print("")

    choice4 = int(input("\033[31m Enter number: \033[0m"))
  #   SHA256
    if choice4 == 1:
        os.system('cls' if os.name == 'nt' else 'clear')
        def sha256_hash(text):
          return hashlib.sha256(text.encode()).hexdigest()

        def main():
          user_input = input("Enter text to hash with SHA-256: ")
          hashed = sha256_hash(user_input)
          print(f"SHA-256 hash: {hashed}")

        if __name__ == "__main__":
          main()
      #MD5
    elif choice4 == 2:
      os.system('cls' if os.name == 'nt' else 'clear')
      def md5_hash(text):
        return hashlib.md5(text.encode()).hexdigest()

      def main():
        user_input = input("Enter text to hash with MD5: ")
        hashed = md5_hash(user_input)
        print(f"MD5 hash: {hashed}")

      if __name__ == "__main__":
        main()
# SHA-1
    elif choice4 == 3:
      os.system('cls' if os.name == 'nt' else 'clear')
      def sha1_hash(text):
        return hashlib.sha1(text.encode()).hexdigest()

      def main():
        user_input = input("Enter text to hash with SHA-1: ")
        hashed = sha1_hash(user_input)
        print(f"SHA-1 hash: {hashed}")

      if __name__ == "__main__":
        main()

    
elif choice == 99:
    print("Thanks for using ")
    time.sleep(2)
    print("Goodbye!")
    time.sleep(2)
    os.system('cls' if os.name == 'nt' else 'clear')
    exit()
else:
    print("Invalid option selected.")
