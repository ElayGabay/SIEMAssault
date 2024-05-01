# SIEMAssault

SIEMAssault is a bash script designed to help you test the effectiveness of your SIEM (Security Information and Event Management) system and firewall configurations by simulating various cyber attacks. This tool allows you to assess your SOC (Security Operations Center) readiness by launching different types of attacks against your network.

![image](https://github.com/ElayGabay/SIEMAssault/assets/140305198/a1c585d0-7218-446f-bc7f-3a32955f4d9e)



## Installation

To use SIEMAssault, follow these steps:

1. Clone the SIEMAssault repository to your local machine:

    ```bash
    git clone https://github.com/your_username/SIEMAssault.git
    ```

2. Navigate to the SIEMAssault directory:

    ```bash
    cd SIEMAssault
    ```


3. Give permissions with chmod   
    ```bash
    chmod +x SIEMAssault.sh
    ```


3. Run the script with sudo:

    ```bash
    sudo ./SIEMAssault.sh
    ```

## Usage

Upon running the script, you will be prompted to choose the type of attack you want to simulate. SIEMAssault currently supports three types of attacks: DDOS, Brute Force, and MITM (Man-In-The-Middle).

Follow the on-screen instructions to select an attack type and provide any additional information required, such as target IP addresses or attack duration.

Please note that SIEMAssault is intended for educational and testing purposes only. Do not use it for any malicious activities.

## Disclaimer

SIEMAssault is provided as-is without any warranty. The authors are not responsible for any damages or legal consequences resulting from the use or misuse of this tool.


