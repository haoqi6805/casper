# CASPER AES256 文件加密模块
采用AES256/EAX算法，对任意格式文件进行加密

### 系统
Raspbian GNU/Linux 11 (bullseye)

### 安装增强功能所需要的库（VBox虚拟机）
```bash
sudo apt update
sudo apt install build-essential gcc make perl dkms
sudo reboot
```

### 下载casper
https://github.com/haoqi6805/casper.git

### 安装vim & ufw
```bash
sudo apt update  
sudo apt install vim ufw fcitx fcitx-googlepinyin
cp vim_config ~/.vimrc  
```

### 搭建虚拟环境
```python
python3 -m venv .venv  
source .venv/bin/activate  
python -m pip install --upgrade pip  
python -m pip install pycryptodomex  
python -m pip install mnemonic  
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
sudo reboot
```

### 开始
```bash
./run.sh
```
