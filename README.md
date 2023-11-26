# Casper File Cryptor
### 硬件
Raspberry Pi 4 Model B

### 系统
Ubuntu 22.04.3 for Rasberry Pi

### 安装软件
```bash
sudo apt update
sudo apt install -y build-essential gcc make perl dkms
sudo apt install -y ufw vim git python3.10-venv
```

### 下载casper
```bash
cd ~
git clone https://github.com/haoqi6805/casper.git
cd ~/casper
mkdir cspr
```

### Python虚拟环境
```python
cd ~/casper
python3 -m venv .venv  
source .venv/bin/activate  
python -m pip install --upgrade pip  
python -m pip install pycryptodomex  
python -m pip install mnemonic  
```

### 配置vim
```bash
cp ~/casper/vim_config ~/.vimrc
```

### 防火墙设置（推荐）
```bash
sudo ufw enable  
sudo ufw default deny
```

### 关闭网络及蓝牙服务（必要时）
```bash
sudo rfkill block all
sudo systemctl mask bluetooth.service  
sudo systemctl mask NetworkManager.service
```

### 重启
```bash
sudo reboot
```

### 开始
```bash
~/casper/run.sh
```
