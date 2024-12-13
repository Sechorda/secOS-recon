#!/bin/bash

# GitHub Package Installer

# Ensure script is run with sudo
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with sudo" 
   exit 1
fi

# Install dependencies
apt-get update
apt-get install -y git wget unzip python3-pip golang curl

# Knock
git clone https://github.com/guelfoweb/knock.git /usr/local/bin/.knock
cd /usr/local/bin/.knock
pip install . --break-system-packages
ln -sf /usr/local/bin/.knock/knock/knockpy.py /usr/local/bin/knockpy

# ffuf
wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -O /tmp/ffuf.tar.gz
mkdir -p /usr/local/bin/.ffuf
tar -xf /tmp/ffuf.tar.gz -C /usr/local/bin/.ffuf ffuf
ln -sf /usr/local/bin/.ffuf/ffuf /usr/local/bin/ffuf
rm /tmp/ffuf.tar.gz

# gospider
wget https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_linux_x86_64.zip -O /tmp/gospider.zip
unzip /tmp/gospider.zip -d /tmp/gospider
mv /tmp/gospider/gospider_v1.1.6_linux_x86_64/gospider /usr/local/bin/gospider
chmod +x /usr/local/bin/gospider
rm -rf /tmp/gospider /tmp/gospider.zip

# Amass
wget https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip -O /tmp/amass.zip
unzip /tmp/amass.zip -d /usr/local/bin
mv /usr/local/bin/amass_Linux_amd64 /usr/local/bin/.amass
ln -sf /usr/local/bin/.amass/amass /usr/local/bin/amass
rm /tmp/amass.zip

# dnsReaper
git clone https://github.com/punk-security/dnsReaper.git /usr/local/bin/.dnsReaper
cd /usr/local/bin/.dnsReaper
pip install -r requirements.txt --break-system-packages
chmod +x main.py
ln -sf /usr/local/bin/.dnsReaper/main.py /usr/local/bin/dnsreaper

# jsluice
go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest
mv /root/go/bin/jsluice /usr/local/bin/.jsluice
ln -sf /usr/local/bin/.jsluice /usr/local/bin/jsluice
rm -rf /root/go

# shortscan
go install -v github.com/bitquark/shortscan/cmd/shortscan@latest
mv /root/go/bin/shortscan /usr/local/bin/shortscan
rm -rf /root/go

# CloudBrute
wget https://github.com/0xsha/CloudBrute/releases/download/v1.0.7/cloudbrute_1.0.7_Linux_x86_64.tar.gz -O /tmp/cloudbrute.tar.gz
mkdir -p /usr/local/bin/.cloudbrute
tar -xf /tmp/cloudbrute.tar.gz -C /usr/local/bin/.cloudbrute
ln -sf /usr/local/bin/.cloudbrute/cloudbrute /usr/local/bin/cloudbrute
rm /tmp/cloudbrute.tar.gz

# Corsy
git clone https://github.com/s0md3v/Corsy.git /usr/local/bin/.corsy
cd /usr/local/bin/.corsy
pip install -r requirements.txt --break-system-packages
echo '#!/bin/bash' > /usr/local/bin/corsy
echo 'python3 /usr/local/bin/.corsy/corsy.py "$@"' >> /usr/local/bin/corsy
chmod +x /usr/local/bin/corsy

# FireProx
git clone https://github.com/ustayready/fireprox /usr/local/bin/.fireprox
cd /usr/local/bin/.fireprox
pip3 install -r requirements.txt --break-system-packages
echo '#!/bin/bash' > /usr/local/bin/fireprox
echo 'python3 /usr/local/bin/.fireprox/fire.py "$@"' >> /usr/local/bin/fireprox
chmod +x /usr/local/bin/fireprox

# Spiderfoot
git clone https://github.com/smicallef/spiderfoot.git /usr/local/bin/.spiderfoot
cd /usr/local/bin/.spiderfoot
pip3 install -r requirements.txt --break-system-packages
echo '#!/bin/bash' > /usr/local/bin/spiderfoot
echo 'python3 /usr/local/bin/.spiderfoot/sf.py "$@"' >> /usr/local/bin/spiderfoot
chmod +x /usr/local/bin/spiderfoot

# Additional pip package installs
pip3 install wafw00f arjun sherlock-project bbot --break-system-packages

# Ensure all tools are accessible
chmod -R 755 /usr/local/bin

echo "GitHub package installation complete!"
