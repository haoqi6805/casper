# Casper File Cryptor
### Device
Raspberry Pi 4 Model B

### System
Ubuntu 22.04.3 for Rasberry Pi

### Install softwares
```bash
sudo apt update
sudo apt install -y build-essential gcc make perl dkms
sudo apt install -y ufw vim git python3.10-venv
```

### Download casper
```bash
cd ~
git clone https://github.com/haoqi6805/casper.git
cd ~/casper
mkdir cspr
```

### Python virtual environment
```python
cd ~/casper
python3 -m venv .venv  
source .venv/bin/activate  
python -m pip install --upgrade pip  
python -m pip install pycryptodomex  
python -m pip install mnemonic  
```

### Vim setting file
```bash
cp ~/casper/vim_config ~/.vimrc
```

### Firewall（recommend）
```bash
sudo ufw enable  
sudo ufw default deny
```

### Turn off network and bluetooth services（when necessary）
```bash
sudo rfkill block all
sudo systemctl mask bluetooth.service  
sudo systemctl mask NetworkManager.service
```

### Restart
```bash
sudo reboot
```

### Run
```bash
~/casper/run.sh
```
