1)Installation steps for binwalk:

sudo apt update
sudo apt install binwalk
git clone https://github.com/ReFirmLabs/binwalk.git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
cd ~/binwalk
sudo ./dependencies/ubuntu.sh
cargo build --release
echo 'export PATH="$PATH:$HOME/binwalk/target/release"' >> ~/.bashrc
source ~/.bashrc

2)Executing Python script:
./analyze_firmware.py Flash_1.03/loader.bin