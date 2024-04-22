# Exploiting Blind SQLi (DVWA) (Security Level: Low)

The Python scripts provide a comprehensive framework for conducting Blind SQL Injection attacks against the Damn Vulnerable Web Application (DVWA). The first script introduces foundational classes and methods to facilitate HTTP sessions, set security levels, parse SQL injection responses, and construct SQL queries dynamically. Building on this foundation, the second script implements a systematic approach to exploit SQL injection vulnerabilities, aiming to extract sensitive database information such as the database name, table names, column details, and ultimately, user credentials. It starts by establishing a testing session with DVWA, then sequentially narrows down the search through a series of crafted SQL queries to identify the database structure and contents, with stages for determining the length and content of database names, enumerating tables and columns, and extracting user passwords. User interaction is integrated for targeted exploration, allowing for the interruption of processes to streamline the data extraction phases. This combination showcases a methodical exploitation process that leverages automation and user input to uncover and exploit vulnerabilities in web applications.

## Disclaimer

The tools and scripts provided in this repository are made available for educational purposes only and are intended to be used for testing and protecting systems with the consent of the owners. The author does not take any responsibility for the misuse of these tools. It is the end user's responsibility to obey all applicable local, state, national, and international laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Under no circumstances should this tool be used for malicious purposes. The author of this tool advocates for the responsible and ethical use of security tools. Please use this tool responsibly and ethically, ensuring that you have proper authorization before engaging any system with the techniques demonstrated by this project.

## Acknowledgments

This project is based on the original [blind_sqli project](https://github.com/StackZeroSec/dvwa/tree/main/blind_sqli) by [StackZeroSec](https://github.com/StackZeroSec). We thank them for their work and contributions to the security community.

## Features

- **Automated SQL Injection Attacks**: Automates the process of conducting Blind SQL Injection to uncover vulnerabilities.
- **Dynamic SQL Query Construction**: Builds SQL queries on the fly to probe the database structure and extract data.
- **Session Management**: Manages HTTP sessions and CSRF tokens to maintain interaction with DVWA under varying security levels.
- **Real-Time Feedback and Interaction**: Provides ongoing feedback and allows for user interaction to refine the data extraction process.
- **Security Level Manipulation**: Adjusts the security level of DVWA to test different strengths of SQL injection defenses.

## Prerequisites

- **Operating System**: These scripts were tested on Kali Linux 2023.4.
- **Python Version**: Requires Python 3.x.
- **Required Python Libraries**:
    - `requests` for HTTP session management.
    - `bs4` (BeautifulSoup) for parsing HTML responses.
    - `enum` for defining enumeration classes easily.
- **Target Application**: Damn Vulnerable Web Application (DVWA): Ensure DVWA is accessible and configured to accept connections for testing.

## Installation

1. **Python Environment Setup**: Ensure Python and pip are installed. Install the required libraries using:
    
    ```bash
    sudo pip install requests beautifulsoup4
    ```
    
2. **Download Scripts**: Clone or download the scripts from the project repository to your local machine.
3. **Configure DVWA**: Set up DVWA to run locally or access a remote instance. Ensure it is configured to be vulnerable to SQL Injection. Alternatively, you can follow the instructions below for DVWA hosted on Try Hack Me.

## DVWA Setup (THM)

1. **Setup VPN connection to DVWA machine in THM.**: [TryHackMe | DVWA](https://tryhackme.com/room/dvwa)
2. **Setup OpenVPN Connection to Access THM's DVWA Machine:**
- Download your OpenVPN configuration file from THM.
- Use a terminal or command prompt to start the OpenVPN connection:
    
    ```bash
    sudo openvpn [Your OpenVPN File].ovpn
    ```
    
1. **Access the DVWA Web Interface:**
    - Open a web browser and navigate to the DVWA machine's IP address provided by THM. The address typically looks like `http://10.10.x.x`, where `x.x` is your specific machine's IP.
    - Log in to DVWA with the following default credentials (or as instructed by THM):
        - Username: `admin`
        - Password: `password`
2. **Configure DVWA for SQL Injection (Blind):**
    - Once logged in, find and click on **DVWA Security** from the left menu.
    - Set the security level to **Low**. This is crucial as the script is designed to work with DVWA under low security settings.
    - Navigate back to the home page and click on **SQL Injection (Blind)** from the left menu to ensure it's ready for testing.
    ![DVWA Security Level Low](/images/DVWA_Security_Level_Low.png)
    
3. **Run Script and Provide Your DVWA IP Address:**
    
    ```bash
    python3 main_low.py
    ```
    
    - Enter the IP address of the DVWA machine when prompted to execute the SQL injection.
4. **Cracking the Obtained Password Hash:**
    - Once you've successfully extracted the password hash for a user, navigate to [CrackStation's website](https://crackstation.net/) and enter the obtained password hash into the textbox.
    - CrackStation will process the hash and, if possible, return the plaintext password associated with that hash. This process works by looking up the hash in a large database of pre-computed hash values and their corresponding plaintext counterparts.

## How It Works

- The first script establishes a session with DVWA, manages CSRF tokens, and sets the security level. It also provides foundational methods for sending crafted SQL queries and interpreting the responses.
- The second script uses the methods defined in the first script to perform detailed enumeration of the database structure. It conducts targeted attacks to extract names of databases, tables, and columns, and retrieves sensitive user data. Throughout this process, it utilizes user input to refine attack vectors and optimize data extraction.

## Output Example

```bash
$ python3 main_low.py
Enter the DVWA server IP address: 10.10.x.x
[+] Length of the database name is 4
[+] Database name discovered: dvwa
[+] Number of tables in the database: 2
         guestbook
         users
Enter the name of the table to analyze: users
[+] Number of columns in 'users': 8
[!] Attempting to accelerate the process. Press CTRL+C when you find the targeted columns.
         userid
         firstname
         lastname
         user
         password
         avatar
         lastlogin
         failedlogi
Enter the username column name: user
Enter the password hash column name: password
[!] To further speed up the process, press CTRL+C when you find the target user
| __________ admin
| __________ gordonb
^C
User discovery halted!
Enter the target username for password hash extraction: admin
[+] Password hash length for 'admin': 32
[+] Password hash for 'admin': 5f4dcc3b5aa765d61d8327deb882cf99
```
![Crackstation](/images/CrackStation_results.png)

## Contributing

If you have an idea for an improvement or if you're interested in collaborating, you are welcome to contribute. Please feel free to open an issue or submit a pull request.

## License

This project is licensed under the GNU General Public (GPL) License - see the [LICENSE](https://github.com/CyberWolfByte/dvwa/blob/main/LICENSE) file for details.
