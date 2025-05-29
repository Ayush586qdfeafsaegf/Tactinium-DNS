# Tactinium-DNS

This guide provides an extremely detailed, step-by-step approach to building a full ecosystem that replicates key aspects of the surface web using entirely open-source components. This ecosystem is designed to be deployable on Virtual Private Servers (VPS) and includes support for custom Top-Level Domains (TLDs).

Disclaimer: This guide is for educational and experimental purposes. Running such an ecosystem carries significant responsibilities. You are solely responsible for the security, legality, and ethical implications of any system you build based on this guide. Always comply with applicable laws and ensure responsible use. This setup does not inherently provide anonymity or privacy beyond what you configure; users must trust the ecosystem operator.

Prerequisites:

Strong Linux system administration skills (command line, package management, service configuration).

Understanding of networking concepts (DNS, IP addressing, firewalls, HTTP/S).

Familiarity with Docker and Docker Compose is highly recommended.

Access to one or more VPS instances.

A (public) domain name for bootstrapping some services (e.g., for Let's Encrypt certs for DoH endpoints, if not using private CA for everything initially).

Part 0: Architecture Overview & Core Concepts

This ecosystem aims to create a parallel "shadow" web space using custom TLDs (e.g., .shadow, .x, .void).

High-Level Architecture:

+-------------------------+      +-------------------------+      +-------------------------+
|     END-USER DEVICES    |----->| CUSTOM RECURSIVE DNS    |----->| POWERDNS AUTHORITATIVE  |
| (Configured Resolver/DoH|      | (e.g., Unbound/pdns-rec)|      | (Serves .shadow, .x)    |
|  + Private Root CA Cert)|      | - Resolves public TLDs  |      | - Manages zones via API |
+-------------------------+      | - Forwards custom TLDs  |      +-----------^-------------+
                                 +-------------------------+                  |
                                                                              |
+-------------------------+                                       +-----------+-------------+
|   REVERSE PROXY (NGINX/ |<---- HTTP/S Traffic ------------------|   POWERDNS-ADMIN (GUI)  |
|   CADDY)                |                                       |   (Manages PowerDNS)    |
| - SSL Termination (Priv CA)                                     +-------------------------+
| - Routes to Services    |
+-----------+-------------+
            |
            |
  +---------V------------------------------------------------------------------+
  |                                 APPLICATION SERVERS (VPSs)                 |
  |                                                                            |
  | +-----------------+  +-----------------+  +-----------------+  +-----------+------+
  | | MAILCOW         |  | WEB HOSTING     |  | SOCIAL MEDIA    |  | IDENTITY (KEYCLOAK|
  | | (mail.host.shadow)|  | (WordPress, etc |  | (Mastodon, etc. |  | AUTHELIA)        |
  | |                   |  | on site.x)      |  | on social.void) |  |                  |
  | +-----------------+  +-----------------+  +-----------------+  +------------------+
  +------------------------------------------------------------------------------------+


Core Components:

Authoritative DNS Server (PowerDNS): Stores and serves DNS records for your custom TLDs.

Recursive DNS Resolver (Unbound/PowerDNS Recursor): Resolves both public TLDs (by querying internet root servers) and your custom TLDs (by querying your authoritative server).

Private Certificate Authority (CA): Issues SSL certificates for your custom TLD domains, as public CAs like Let's Encrypt won't.

Reverse Proxy (Nginx/Caddy): Manages incoming web traffic, terminates SSL using your private CA's certificates, and routes requests to backend applications.

Application Servers: Host mail (Mailcow), websites (CMS), social media platforms, identity services, etc.

Part 1: Domain Infrastructure

This section details setting up the DNS backbone for your custom TLDs.

1.1. Choosing your Custom TLDs

Select TLDs that are unlikely to be delegated by ICANN in the future to avoid collisions. Examples: .shadow, .meta, .internal, .corp, .node, .void, .x.

Avoid using existing or reserved TLDs (e.g., .com, .org, .local, .example).

A good resource to check for reserved/existing TLDs is the IANA Root Zone Database and RFC 2606 / RFC 6761 (for special-use names).

For this guide, we'll use .shadow and .x as examples.

1.2. PowerDNS Authoritative Server Setup

We'll use PowerDNS with a MySQL backend. This server will be authoritative for .shadow, .x, etc.

VPS: 1 vCPU, 2GB RAM, 20GB SSD (minimum). Let's call its public IP A.B.C.D.

Installation (Debian/Ubuntu example):

sudo apt update
sudo apt install pdns-server pdns-backend-mysql mysql-server
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

MySQL Setup:

sudo mysql -u root -p
# Inside MySQL prompt:
CREATE DATABASE powerdns;
CREATE USER 'powerdns'@'localhost' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON powerdns.* TO 'powerdns'@'localhost';
FLUSH PRIVILEGES;
EXIT;
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Import PowerDNS schema:

sudo mysql -u powerdns -p powerdns < /usr/share/doc/pdns-backend-mysql/schema.mysql.sql
# Enter 'your_strong_password' when prompted
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

PowerDNS Configuration (/etc/powerdns/pdns.conf):
Edit pdns.conf and ensure/add these lines:

launch=gmysql
gmysql-host=localhost
gmysql-dbname=powerdns
gmysql-user=powerdns
gmysql-password=your_strong_password

# Listen on public IP
local-address=0.0.0.0 # Or specific IP A.B.C.D
# local-port=53 # Default

# Security settings (adjust as needed)
# query-logging=yes # For debugging, disable in production for performance/privacy
# loglevel=4 # For debugging
# version-string=anonymous # Optional: hide version

# Enable API for PowerDNS-Admin
api=yes
api-key=your_very_secret_api_key # Change this!
webserver=yes
webserver-address=127.0.0.1 # Or specific IP if PowerDNS-Admin is on another host
webserver-port=8081
webserver-allow-from=127.0.0.1, ::1 # Add IP of PowerDNS-Admin server if external
# If PowerDNS-Admin is on the same server, 127.0.0.1 is fine.
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Ini
IGNORE_WHEN_COPYING_END

Start and Enable PowerDNS:

sudo systemctl restart pdns
sudo systemctl enable pdns
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Check status: sudo systemctl status pdns
Check logs: sudo journalctl -fu pdns

1.3. PowerDNS-Admin (GUI Management)

Easiest to run via Docker on the same or another VPS.

Installation (Docker):

# Install Docker and Docker Compose if not already present
# sudo apt install docker.io docker-compose

mkdir ~/powerdns-admin && cd ~/powerdns-admin
wget https://raw.githubusercontent.com/ngoduykhanh/PowerDNS-Admin/master/docker-compose.yml

# Edit docker-compose.yml if needed (e.g., port, volumes)
# By default, it uses SQLite. For production, consider PostgreSQL backend for PowerDNS-Admin itself.
# For now, default SQLite is fine for PowerDNS-Admin's own data.

sudo docker-compose up -d
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Access PowerDNS-Admin at http://<your_powerdns_admin_vps_ip>:80 (or configured port).
Default credentials (change immediately): admin / admin_password_to_change_at_login_screen (check latest PowerDNS-Admin docs for default, it may change).

Connecting PowerDNS-Admin to PowerDNS Server:

Login to PowerDNS-Admin.

Go to "Settings" -> "PowerDNS".

Type: Native (if your PowerDNS version >= 4.x)

PDNS API URL: http://A.B.C.D:8081 (or http://127.0.0.1:8081 if on same host and webserver-address in pdns.conf allows it).

PDNS API Key: your_very_secret_api_key (from pdns.conf).

Save and test connection.

Creating Custom TLD Zones and Glue Records:
This step is crucial: your custom TLDs need NS records pointing to themselves.

In PowerDNS-Admin, go to "New Domain".

Domain: shadow (Master type).

This creates the .shadow zone.

Add records to shadow zone:

ns1.shadow (Type A) -> A.B.C.D (IP of your PowerDNS authoritative server)

ns2.shadow (Type A) -> E.F.G.H (IP of a secondary PowerDNS authoritative server, if you have one for redundancy)

shadow. (Type NS) -> ns1.shadow.

shadow. (Type NS) -> ns2.shadow. (if you have a secondary)

Repeat for .x TLD: create zone x, add ns1.x (A record -> A.B.C.D), and NS record x. -> ns1.x..

Now you can add domains like example.shadow or mycorp.x in PowerDNS-Admin.
Example: Create zone example.shadow.

example.shadow. (Type SOA) -> Auto-created

example.shadow. (Type NS) -> ns1.shadow.

www.example.shadow. (Type A) -> IP of your webserver for this site.

mail.example.shadow. (Type A) -> IP of your mail server.

example.shadow. (Type MX, Prio 10) -> mail.example.shadow.

1.4. Custom Recursive DNS Resolver

This resolver will be used by end-users. It queries public DNS for regular domains and your PowerDNS server for custom TLDs. We'll use Unbound.

VPS: 1 vCPU, 1-2GB RAM. Let its public IP be I.J.K.L. (This can be the same VPS as PowerDNS authoritative if resources allow, but separation is better for robustness).

Installation (Debian/Ubuntu):

sudo apt update
sudo apt install unbound
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Unbound Configuration (/etc/unbound/unbound.conf or in /etc/unbound/unbound.conf.d/myconfig.conf):

server:
    verbosity: 1
    interface: 0.0.0.0 # Listen on all interfaces, or specific IP I.J.K.L
    port: 53
    do-ip4: yes
    do-ip6: no # Or yes if you have IPv6
    do-udp: yes
    do-tcp: yes

    # Access control: Allow queries from your users/networks
    access-control: 0.0.0.0/0 refuse       # Default deny
    access-control: 127.0.0.0/8 allow     # Allow localhost
    access-control: 192.168.0.0/16 allow  # Example: Allow private network
    # Add specific IPs or ranges of your users if you want to restrict access
    # For a public-facing resolver (less secure, risk of abuse):
    # access-control: 0.0.0.0/0 allow

    # Root hints (usually pre-configured)
    root-hints: "/usr/share/dns/root.hints" # Ensure this file exists and is current
                                            # sudo apt install dns-root-data; wget -O root.hints https://www.internic.net/domain/named.root

    # Harden (DNSSEC validation, etc.)
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    val-permissive-mode: no # For custom TLDs without DNSSEC, might need to adjust or sign them.

    # Private domains (prevents leaking queries for these to public DNS)
    private-domain: "shadow"
    private-domain: "x"

    # Forward zones for custom TLDs to your PowerDNS Authoritative Server
    forward-zone:
        name: "shadow."
        forward-addr: A.B.C.D@53  # IP of your PowerDNS authoritative server
        # forward-addr: E.F.G.H@53 # Secondary PowerDNS server if any

    forward-zone:
        name: "x."
        forward-addr: A.B.C.D@53
        # forward-addr: E.F.G.H@53

    # Optional: Enable caching
    msg-cache-size: 50m
    rrset-cache-size: 100m

    # Optional: Prefetch popular queries
    prefetch: yes
    prefetch-key: yes
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Aconf
IGNORE_WHEN_COPYING_END

Note on DNSSEC for custom TLDs: Proper DNSSEC for custom TLDs requires setting up a trust anchor for your custom root. This is complex. For simplicity initially, you might run without DNSSEC validation for your custom TLDs or use domain-insecure: "shadow" and domain-insecure: "x" in Unbound if validation fails. However, this reduces security. A better long-term solution is to DNSSEC-sign your custom zones and configure your Unbound resolver with the trust anchors for these zones.

Start and Enable Unbound:

sudo systemctl restart unbound
sudo systemctl enable unbound
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Test from another machine: dig @I.J.K.L www.google.com and dig @I.J.K.L www.example.shadow.

1.5. End-User Configuration for Seamless Access

Users need to point their devices/browsers to your custom recursive resolver (I.J.K.L) and trust your Private Root CA (see Part 3 for CA setup).

Option 1: System-level DNS Configuration:

Linux: Modify /etc/resolv.conf (directly or via systemd-resolved or NetworkManager). E.g., nameserver I.J.K.L.

Windows/macOS: Change DNS settings in Network Preferences to point to I.J.K.L.

Option 2: DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT):
This is more secure and portable. You'll need a DoH/DoT server fronting your Unbound resolver.

Tools: dnsdist (powerful), nginx (with ngx_http_v3_module for DoH3), cloudflared (as a server), dnsproxy (Adguard).

Example using dnsdist (on the Unbound server I.J.K.L or a dedicated frontend):

sudo apt install dnsdist
# Edit /etc/dnsdist/dnsdist.conf
newServer{address="127.0.0.1:5300", qps=1000} # Point to Unbound on a different port or IP
# Unbound would listen on 127.0.0.1:5300, dnsdist on I.J.K.L:53 for plain DNS

# For DoH:
addDOHLocal("I.J.K.L:443", "/etc/ssl/your_doh_cert.pem", "/etc/ssl/your_doh_key.pem", "/dns-query")
# The cert for DoH endpoint (e.g., dns.yourpublicdomain.com) initially needs to be from a public CA like Let's Encrypt.
# Or, use your private CA cert if users already trust it.
# The DoH endpoint could be e.g., https://dns.myservice.shadow/dns-query if clients have the CA cert.
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Users configure DoH in browsers (Firefox, Chrome) or OS (Windows 11, Android, iOS).

Firefox: Settings -> Network Settings -> Enable DNS over HTTPS -> Custom: https://your_doh_server_address/dns-query

Option 3: Local Resolver on Client: Advanced users can run Unbound locally and configure forward zones.

Part 2: Mail Infrastructure (Mailcow)

Mailcow provides a full-featured mail server suite using Docker.

VPS: 2-4 vCPU, minimum 6GB RAM (8GB+ recommended), 50GB+ SSD. Let its IP be M.N.O.P.

Prerequisites: Docker, Docker Compose. A (public) FQDN for Mailcow host initially (e.g., mail.yourpublicdomain.com) can simplify initial SSL with Let's Encrypt for Mailcow's own UI, even if mail domains are custom. Alternatively, use your private CA from the start.

DNS Records (in PowerDNS-Admin for example.shadow):
Assume Mailcow hostname will be mail.example.shadow.

mail.example.shadow. (Type A) -> M.N.O.P

example.shadow. (Type MX, Prio 10) -> mail.example.shadow.

SPF: example.shadow. (Type TXT) -> "v=spf1 mx ~all" (or a:mail.example.shadow)

DKIM: Mailcow will generate this. Add it as a TXT record (e.g., dkim._domainkey.example.shadow.).

DMARC: _dmarc.example.shadow. (Type TXT) -> "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.shadow" (adjust policy p= as needed).

Autoconfig/Autodiscover SRV/CNAME records for easier client setup (see Mailcow docs).

Mailcow Installation:

sudo apt install git acl # and Docker/Docker Compose
git clone https://github.com/mailcow/mailcow-dockerized && cd mailcow-dockerized
./generate_config.sh # Follow prompts
# Set mailcow hostname to e.g., mail.example.shadow
# Choose timezone
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Edit mailcow.conf:

MAILCOW_HOSTNAME=mail.example.shadow

SKIP_LETS_ENCRYPT=n (if mail.example.shadow is somehow resolvable publicly for LE, or if you're trying for a public TLD hostname for Mailcow itself).

SKIP_LETS_ENCRYPT=y (if mail.example.shadow uses a private TLD, which is our case). You'll need to provide SSL certs manually.

SSL for Mailcow with Custom TLDs:
Since mail.example.shadow is a custom TLD, Let's Encrypt won't work.

Generate SSL certs for mail.example.shadow using your Private CA (see Part 3.3).
You'll get mail.example.shadow.crt, mail.example.shadow.key, and your CA chain ca.pem.

Place them in mailcow-dockerized/data/assets/ssl/:

cert.pem: Your server certificate (mail.example.shadow.crt).

key.pem: Your server private key (mail.example.shadow.key).

chain.pem (or similar name, check Mailcow docs): Your intermediate and root CA certs concatenated.

In mailcow.conf, ensure SKIP_LETS_ENCRYPT=y.

If Mailcow is already running and you update certs, restart relevant services:
docker-compose restart nginx-mailcow postfix-mailcow dovecot-mailcow

Start Mailcow:

sudo docker-compose pull
sudo docker-compose up -d
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Access Mailcow UI: https://mail.example.shadow (browser must trust your Private CA). Default login: admin / moohoo.

Adding Mail Domains (e.g., example.shadow, mycorp.x):

In Mailcow UI: Configuration -> Mail Setup -> Domains -> Add domain.

Enter example.shadow. Add users, aliases.

DKIM keys will be generated; add them to your PowerDNS for example.shadow.

Repeat for mycorp.x or other custom TLD domains.

Client Configuration:
Users configure clients (Thunderbird, Outlook, mobile) with:

IMAP server: mail.example.shadow (Port 993, SSL/TLS)

SMTP server: mail.example.shadow (Port 465, SSL/TLS, or 587 STARTTLS)

Username: user@example.shadow

Password: user's password.
Clients must trust your Private CA, or manually accept the self-signed/private certificate.

Part 3: Web Hosting & Content

3.1. Open-Source CMS Platforms:

Deploy these on separate VPSs or shared app servers, often using Docker.

WordPress: PHP, MySQL/MariaDB. (LAMP/LEMP stack).

Docker: wordpress official image + mysql or mariadb image.

Ghost: Node.js. Modern publishing.

Docker: ghost official image.

Hugo/Jekyll/Pelican: Static Site Generators. Content written in Markdown.

Build locally or via CI/CD, deploy static files to a web server (Nginx, Caddy, Apache). Very performant and secure.

Nextcloud/OwnCloud: File hosting, collaboration (like Google Drive/Dropbox). PHP-based.

Docker: nextcloud official image.

MediaWiki: For wikis (like Wikipedia). PHP-based.

Discourse/Flarum: Forum software. Ruby/JS (Discourse), PHP (Flarum).

3.2. Reverse Proxies (Nginx or Caddy)

A reverse proxy (RP) is essential. Let its IP be R.P.S.T.

Listens on port 80/443.

Terminates SSL using certificates from your Private CA.

Routes traffic to appropriate backend CMS/app servers.

Can be on a dedicated VPS or co-located if resources permit.

Nginx Example:
Install Nginx: sudo apt install nginx
Configuration for blog.example.shadow (proxying to a WordPress backend at 10.0.0.5:8080):
/etc/nginx/sites-available/blog.example.shadow.conf:

server {
    listen 80;
    server_name blog.example.shadow;
    return 301 https://$host$request_uri; # Redirect HTTP to HTTPS
}

server {
    listen 443 ssl http2;
    server_name blog.example.shadow;

    ssl_certificate /etc/ssl/private_ca/certs/blog.example.shadow.pem; # Your signed cert
    ssl_certificate_key /etc/ssl/private_ca/keys/blog.example.shadow.key; # Your private key
    ssl_trusted_certificate /etc/ssl/private_ca/ca_chain.pem; # Your CA chain for OCSP stapling

    # SSL hardening (use a tool like Mozilla SSL Config Generator)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    # ... more SSL settings

    location / {
        proxy_pass http://10.0.0.5:8080; # Backend app
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Nginx
IGNORE_WHEN_COPYING_END

Enable site: sudo ln -s /etc/nginx/sites-available/blog.example.shadow.conf /etc/nginx/sites-enabled/
Test config: sudo nginx -t
Reload Nginx: sudo systemctl reload nginx

Caddy Example:
Install Caddy (see official Caddy docs: caddyserver.com).
Caddyfile example:

blog.example.shadow {
    # Caddy can manage certs from a private CA using the 'tls' directive
    # Option 1: Manually specify certs
    tls /etc/ssl/private_ca/certs/blog.example.shadow.pem /etc/ssl/private_ca/keys/blog.example.shadow.key {
        # Optionally specify your CA's root if Caddy needs to build the chain
        # ca /etc/ssl/private_ca/root_ca.pem
    }

    # Option 2: Integrate with ACME-enabled private CA like Smallstep step-ca
    # tls {
    #    acme_ca https://your.step.ca.server/acme/acme/directory
    #    # or other internal automation options
    # }

    reverse_proxy 10.0.0.5:8080
}

# Caddy automatically handles HTTP to HTTPS redirection
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Caddy
IGNORE_WHEN_COPYING_END

Run Caddy: caddy run (or use systemd service).

3.3. SSL for Custom TLDs: Private Certificate Authority (CA)

This is critical. Public CAs will not issue certs for .shadow, .x, etc.
We'll use step-ca (Smallstep CA) for a robust private CA.

Setup step-ca Server (on a dedicated, secured VPS):

Install step-cli and step-ca (https://smallstep.com/docs/installation).

Initialize CA:

# On the CA server
# Name your CA (e.g., "ShadowNet Root CA")
# DNS Name/IP: The address clients will use to reach the CA (e.g., ca.yourpublicdomain.com OR an IP)
# Provisioner: admin@example.com (your admin email)
step ca init --name "ShadowNet Root CA" --dns "ca.example.shadow,localhost" \
             --address ":8443" --provisioner "admin@example.com" \
             --password-file ca_password.txt # Securely store this password
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

This creates ca.json, certs/, secrets/ etc.
The Root CA certificate will be in certs/root_ca.crt. This is the certificate end-users must install.

Run step-ca:

step-ca $(pwd)/config/ca.json --password-file ca_password.txt
# Or configure it to run as a systemd service
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Configure step-cli to talk to your CA (usually done automatically if step ca init was run locally, or by step ca bootstrap).

Issuing Server Certificates (e.g., for blog.example.shadow):
Do this on the server needing the certificate (e.g., the Reverse Proxy), or generate centrally and distribute securely.

Install step-cli on the RP server.

Bootstrap step-cli to trust your CA:

# Provide Root CA cert URL or file path
step ca bootstrap --ca-url https://ca.example.shadow:8443 --fingerprint <ROOT_CA_FINGERPRINT>
# Get fingerprint from CA server: step certificate fingerprint certs/root_ca.crt
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Obtain a certificate:

# Using ACME (if step-ca is configured with an ACME provisioner)
# (Requires blog.example.shadow to resolve to this machine and be reachable)
# step ca certificate blog.example.shadow blog.crt blog.key --provisioner acme

# Or using a JWT provisioner (more common for internal services)
# First, get a token from your CA admin (e.g., using a one-time token provisioner)
# On CA server: step ca token blog.example.shadow --provisioner <your_provisioner_name>
# On RP server (with the token):
step ca certificate blog.example.shadow blog.example.shadow.pem blog.example.shadow.key --token <OBTAINED_TOKEN> --kty RSA
# Place certs in paths used by Nginx/Caddy.
# The .pem file will contain the cert and the intermediate chain.
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Distributing and Trusting the Root CA Certificate (root_ca.crt):

Make certs/root_ca.crt (from step-ca server) available to users (e.g., download from a known web page).

Instructions for users (CRITICAL):

Windows: Double-click root_ca.crt, Install Certificate -> Current User or Local Machine -> "Place all certificates in the following store" -> Browse -> "Trusted Root Certification Authorities".

macOS: Double-click root_ca.crt, Keychain Access opens. Add to "System" keychain. Find cert, Get Info, expand "Trust", set "When using this certificate" to "Always Trust".

Linux (system-wide):

sudo cp root_ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Firefox: Settings -> Privacy & Security -> Certificates -> View Certificates -> Authorities -> Import -> Select root_ca.crt -> "Trust this CA to identify websites".

Android/iOS: Process varies. Usually Settings -> Security -> Encryption & Credentials -> Install a certificate. May require cert to be in DER format or specific naming. This is often the trickiest part.

Part 4: Social Media Layer (Federated/Decentralized)

Host platforms like Mastodon or Pleroma on your custom TLDs.

Platform Options:

Mastodon: (Ruby, PostgreSQL, Redis) - Popular, feature-rich, resource-heavy.

Official docs: https://docs.joinmastodon.org/

Docker setup is common.

Pleroma/Akkoma: (Elixir/Erlang, PostgreSQL) - Lighter, compatible with Mastodon API.

Pleroma: https://pleroma.social/ (Akkoma is a popular fork: https://akkoma.social/)

Often installed from source or OTP releases. Docker options exist.

Misskey: (Node.js, PostgreSQL, Redis, Elasticsearch opt.) - Feature-rich, different UI/UX.

https://misskey-hub.net/

Docker setup is common.

General Setup (Example: Akkoma on social.example.shadow):

VPS: 2-4 vCPU, 4-8GB RAM (Akkoma is lighter than Mastodon).

DNS: In PowerDNS-Admin, create A record social.example.shadow -> IP of this VPS.

Installation: Follow official Akkoma installation guide. (Usually involves setting up PostgreSQL, compiling Akkoma, configuring it).

During setup, specify social.example.shadow as the instance domain.

Reverse Proxy:

Configure Nginx/Caddy on your RP server (or locally on Akkoma VPS if it's also the RP) to proxy to Akkoma.

Example Nginx snippet for Akkoma (adapt from official docs):

# In your server block for social.example.shadow
location / {
    proxy_pass http://localhost:4000; # Akkoma's default port
    # ... other proxy headers as per Akkoma docs
}
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Nginx
IGNORE_WHEN_COPYING_END

Ensure SSL is configured using your Private CA certificate for social.example.shadow.

Federation:

Instances within your .shadow ecosystem can federate with each other seamlessly if they all use your custom DNS resolver.

Federation with public Mastodon/ActivityPub instances is problematic: they cannot resolve social.example.shadow unless they manually add your DNS resolver or specific host entries, which is unlikely. Your instance will mostly be an island or federate only within your ecosystem.

Part 5: User Access Layer

Ensure users can easily access your ecosystem.

Browser-based Instructions (Recap & Emphasis):

DNS Configuration: System-level or Browser DoH pointing to I.J.K.L (your recursive resolver) or its DoH endpoint (e.g., https://dns.myservice.shadow/dns-query).

Private Root CA Trust: Users must install and trust your root_ca.crt. Provide clear, step-by-step instructions for various OS and browsers (as in Part 3.3). This is non-negotiable for a warning-free experience.

Optional: Lightweight Desktop/Mobile Browser or Extension:

Concept: Pre-configure a browser/extension to simplify access.

Features:

Automatically use your custom DoH/DoT server.

Bundle and trust your Private Root CA certificate.

Optionally, provide bookmarks or a default homepage for your ecosystem.

Development:

Browser Fork: Forking Chromium or Firefox is a massive undertaking.

Electron/Tauri App: Build a simpler custom browser shell using web technologies. Still significant work.

Browser Extension (WebExtensions API):

Can use proxy.onRequest to redirect DNS lookups for your custom TLDs via your DoH server (requires dns permission if available, or complex proxy rules).

Cannot directly install Root CAs. User still needs to do that manually. An extension can guide them.

Can provide a UI for managing settings or bookmarks.

Reality Check: This is a substantial development effort. Focusing on clear instructions for standard browsers is more practical initially.

Alternative: Provide downloadable configuration profiles (e.g., for macOS, iOS) or scripts that automate DNS and CA installation where possible.

Part 6: Security & Identity

6.1. Authentication and Identity Layers:

Provide SSO or centralized user management for services within your ecosystem.

Options:

Keycloak: (Java) - Very powerful, full OpenID Connect (OIDC), OAuth2, SAML provider. User federation, social login, fine-grained permissions. Resource-intensive.

https://www.keycloak.org/

Run via Docker. jboss/keycloak or quay.io/keycloak/keycloak.

Authelia: (Go) - Lighter SSO provider, focuses on 2FA, good for protecting web apps with reverse proxies.

https://www.authelia.com/

Integrates with Nginx, Traefik, Caddy. Run via Docker.

Authentik: (Python/Go) - Modern, comprehensive IDP.

https://goauthentik.io/

Run via Docker.

Integration Example (Authelia with Nginx):

Set up Authelia (e.g., auth.example.shadow). Configure users, OIDC clients/Relying Parties.

Protect an application (e.g., protectedapp.example.shadow) using Nginx:
/etc/nginx/sites-available/protectedapp.example.shadow.conf:

server {
    # ... SSL config for protectedapp.example.shadow ...
    server_name protectedapp.example.shadow;

    location / {
        # Forward authentication to Authelia
        auth_request /authelia; # Authelia's auth endpoint
        auth_request_set $user $upstream_http_remote_user;
        auth_request_set $groups $upstream_http_remote_groups;
        # ... other auth_request_set variables

        proxy_pass http://backend_for_protectedapp;
    }

    location = /authelia {
        internal;
        proxy_pass http://authelia_server_address/api/verify; # Authelia verification endpoint
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URL $request_uri;
        # ... other headers for Authelia
    }
}
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Nginx
IGNORE_WHEN_COPYING_END

Users accessing protectedapp.example.shadow will be redirected to Authelia for login.

6.2. Anonymization Options (for .shadow use)

Disclaimer: The ecosystem itself isn't inherently anonymous. The operator can see traffic. These are for users wanting to access it with more privacy from external observers.

VPN (WireGuard/OpenVPN):

Set up a VPN server (e.g., vpn.example.shadow).

Configure the VPN server to use your custom recursive DNS resolver (I.J.K.L).

Users connect to the VPN. All their traffic (including DNS for .shadow domains) routes through the VPN server.

This hides their access to .shadow from their local ISP.

Tor Bridges/Onion Services (Advanced & Different Goal):

Accessing .shadow via Tor: Users connect to Tor network first, then their Tor exit node attempts to resolve .shadow domains. This will fail unless the exit node is configured for your DNS (unlikely).

Hosting services as Onion Services: Instead of .shadow domains, services get .onion addresses. Accessible only via Tor Browser. This provides anonymity for service location and user access. This is an alternative to custom TLDs, not a direct complement for DNS-based access.

Bridge for the Custom DNS Resolver: One could theoretically set up a Tor bridge that provides access to the custom recursive DNS resolver. Complex and niche.

Focus: For most private .shadow use, a VPN configured to use the custom DNS is the most straightforward way to add a layer of privacy from external network observers.

Part 7: Automation & Management

7.1. Configuration Automation:

Ansible: (Python, Agentless)

Excellent for provisioning VPSs, installing software, managing config files, deploying applications.

Write playbooks for:

Setting up PowerDNS, Unbound.

Deploying Nginx/Caddy and configuring reverse proxy rules.

Installing Docker, pulling images, running containers.

Managing user accounts, firewall rules.

Example Task (install Nginx):

- name: Install Nginx
  ansible.builtin.apt:
    name: nginx
    state: present
    update_cache: yes
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Yaml
IGNORE_WHEN_COPYING_END

Docker & Docker Compose:

Containerize as many applications as possible (Mailcow, PowerDNS-Admin, CMSs, social media apps, Keycloak, etc.).

docker-compose.yml files define multi-container application stacks, simplifying deployment and management.

Example: Mailcow is already fully Dockerized.

Terraform: (HashiCorp, Go)

Infrastructure as Code (IaC) for provisioning and managing cloud resources (VPSs, networks, firewalls) across providers (Hetzner, Linode, DO, AWS, etc.).

Define your desired infrastructure in HCL (HashiCorp Configuration Language).

Example (conceptual for a VPS on DO):

provider "digitalocean" {
  token = var.do_token
}

resource "digitalocean_droplet" "dns_server" {
  image  = "ubuntu-22-04-x64"
  name   = "powerdns-authoritative-01"
  region = "fra1"
  size   = "s-1vcpu-2gb"
  # ... ssh keys, user_data for cloud-init
}
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Terraform
IGNORE_WHEN_COPYING_END

7.2. Optional: Admin Panel Dashboard

A central place to monitor and manage your ecosystem.

Concept:

Display health status of key services (DNS, Mail, Web RPs).

Quick links to individual admin UIs (PowerDNS-Admin, Mailcow, Keycloak, etc.).

Basic server metrics (CPU, RAM, disk usage).

Tools:

Portainer: (Docker) Excellent for managing Docker environments (containers, images, volumes, networks).

Cockpit Project: (Linux) Web-based server management UI. Good for individual server admin.

Grafana + Prometheus: For advanced metrics collection and visualization.

Prometheus scrapes metrics from exporters (e.g., node_exporter for server stats, specialized exporters for apps).

Grafana queries Prometheus to build dashboards.

Custom Dashboard: Build with Flask/Django (Python), Express (Node.js), or PHP + a frontend framework (Vue, React, Svelte). Can integrate with service APIs.

Part 8: Funding, Cost, and Resource Estimation

8.1. VPS Providers:

Hetzner Cloud: Excellent price/performance, especially in Europe.

Linode (Akamai): Reliable, good support, global presence.

DigitalOcean: User-friendly, good for developers, global presence.

Vultr: Competitive pricing, wide range of locations.

OVHcloud: Large scale, often budget-friendly options.

8.2. Estimated Monthly Costs (Example for a Small-Medium Ecosystem):

DNS Servers:

Authoritative (PowerDNS): 1x Small VPS (1-2 vCPU, 2GB RAM) ~ $5-10/month.

Recursive (Unbound): 1x Small VPS (1 vCPU, 1-2GB RAM) ~ $5-10/month.

Redundancy: Double this for HA DNS ($20-40/month total for DNS).

Mail Server (Mailcow):

1x Medium VPS (2-4 vCPU, 8GB RAM, 80GB SSD) ~ $15-30/month.

Web & App Hosting (Reverse Proxy, CMS, Social, Identity):

Reverse Proxy: 1x Small VPS (1-2 vCPU, 2GB RAM) ~ $5-10/month (can be beefier if high traffic).

General App Server (WordPress, Ghost, Keycloak/Authelia): 1-2x Medium VPS (2 vCPU, 4GB RAM) ~ $10-20/month each.

Mastodon (if used): Needs its own Medium/Large VPS (4 vCPU, 8-16GB RAM) ~ $20-60/month. Pleroma/Akkoma can use a smaller one.

Bandwidth:

Most providers include 1TB-10TB/month per VPS. Overage costs vary ($0.01-0.02/GB). Monitor usage.

Backups & Redundancy:

VPS Snapshots/Backups: Typically 20-30% of server cost. E.g., a $10 VPS might have $2-3/month backup cost.

Off-site Backups (e.g., Backblaze B2, Wasabi S3): Cost per GB stored (e.g., $0.005/GB/month) + transfer. For 100GB, ~ $0.50/month + egress.

Total Estimated Monthly Cost Ranges:

Minimal Viable (1 DNS, 1 Mail, 1 Web/App on shared/small VPSs): ~$30-50/month + backups.

Small-Medium with some Redundancy (2 DNS, 1 Mail, 1 RP, 2 App Servers): ~$70-150/month + backups.

Larger with Mastodon: Add ~$30-60/month.

Yearly: Multiply monthly by 12. Some providers offer discounts for yearly payments.

8.3. Potential Monetization or Sustainability Options:

Donations: Patreon, Liberapay, Ko-fi, Open Collective. Crypto donations.

Membership/Subscription: Offer "premium" access or features (larger mailboxes, more web hosting resources, managed app hosting within your ecosystem).

Community Contributions: Skilled users can contribute time to development, moderation, support.

"Vanity" Domain Sales (if you control TLDs like .x): Sell subdomains under your custom TLDs (e.g., coolname.x). Requires a clear policy.

Grants/Sponsorships: If the ecosystem serves a specific community or purpose, seek grants.

Part 9: Client Ecosystem

How users interact with and discover content on your shadow web.

9.1. Accessing the Shadow Web:

Desktop Clients:

Standard browsers (Firefox, Chrome, Edge, Safari) correctly configured for DNS and Private CA trust.

Web Portals:

A central "portal" site (e.g., portal.example.shadow or home.shadow).

Features: Directory of services, search engine (see below), news/announcements, links to help pages (CA cert download, DNS setup).

Mobile Apps:

Mobile browsers (Firefox for Android, Brave) supporting custom DoH and allowing CA import.

Dedicated apps for services (Tusky for Mastodon, Nextcloud app) configured to point to your .shadow instance URLs.

Search Engine for the Shadow Ecosystem:

Deploy an open-source search engine crawler/indexer (e.g., YaCy, SearxNG configured for your TLDs).

YaCy can run in peer-to-peer mode within your ecosystem.

SearxNG is a metasearch engine; you'd configure it to primarily query an index of your shadow sites if you build one.

9.2. Federation and Interconnection:

ActivityPub: Social media platforms (Mastodon, Pleroma, Misskey) within your ecosystem will federate with each other naturally if they can resolve each other's .shadow domains.

Matrix (Decentralized Chat): Host a Matrix homeserver (Synapse, Dendrite, Conduit) on a custom TLD (e.g., chat.example.shadow). It can federate with other Matrix servers (public or private) if they can reach it (might need public-facing federation listeners or specific peering).

DNS Peering with other Shadow Roots:

If other independent "shadow root" ecosystems exist, you could arrange DNS peering.

Your recursive resolver would forward queries for their custom TLDs to their authoritative servers, and vice-versa.

Requires trust, coordination, and compatible policies.

Inter-Service Communication: Services within your ecosystem can use their .shadow hostnames to communicate, provided they all use the custom DNS resolver.

Part 10: Compliance, Legality & Ethics

Critical Disclaimer & Considerations:

You are the Operator: You are responsible for the infrastructure, its security, and the content hosted or transiting through it (to the extent your local laws hold service providers liable).

No Inherent Anonymity: This setup does NOT automatically make users or services anonymous. The operator(s) of the DNS, mail, and proxy servers have significant visibility into traffic patterns and potentially content. True anonymity requires tools like Tor or I2P.

Responsible Use Policy: Clearly define and enforce an Acceptable Use Policy (AUP) for your ecosystem. Prohibit illegal activities, harassment, malware distribution, etc.

Legal Jurisdiction: Your VPS locations and your own location determine applicable laws. Understand your legal obligations regarding data privacy (e.g., GDPR if serving EU users), content takedowns, law enforcement requests.

Custom TLDs are Not Magic: Using .shadow or .x does not grant immunity from laws. These TLDs are private conventions; they have no official standing with ICANN or global internet governance.

Security is Paramount:

Secure all servers: Keep OS and software updated, use strong passwords, SSH keys, firewalls (UFW, nftables).

Protect your Private CA: The Root CA key is the cornerstone of trust. Keep it offline or highly secured. Compromise means all issued certs are untrusted.

Monitor for abuse and security incidents.

Trust Model: Users must explicitly trust:

Your DNS resolution (that you're not redirecting or snooping).

Your Private Root CA (that you're not issuing fraudulent certs for man-in-the-middle attacks).

Your service operations (mail, web hosting, etc.).

Ethical Implications: Consider the purpose of your ecosystem. Is it for private community, experimentation, or something else? Be transparent with users about how it operates.

Content Liability: Depending on jurisdiction, you might be held liable for user-generated content. Moderation capabilities for social platforms are important.

Scalability and Maintenance: This is a significant undertaking to maintain long-term. Plan for updates, troubleshooting, and potential growth.

No Guarantees: This guide provides a technical blueprint. Success depends on careful implementation, ongoing maintenance, and responsible operation.

This guide provides a comprehensive framework. Each component (PowerDNS, Mailcow, Nginx, step-ca, etc.) has extensive documentation of its own that you will need to consult for fine-tuning and advanced configurations. Start small, test thoroughly at each step, and gradually expand your ecosystem. Good luck!
