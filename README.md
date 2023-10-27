# casper

### 系统
Ubuntu 22.04.1 LTS

### 下载casper
https://github.com/haoqi6805/casper.git

### 安装Vim
```bash
sudo apt update  
sudo apt install vim  
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
### 开始
```bash
./run.sh
```
