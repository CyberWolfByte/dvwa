# Blind SQL Injection With Binary Search (DVWA) (Security Level: Low)

The revised Python script enhances the efficiency of Blind SQL Injection attacks against the Damn Vulnerable Web Application (DVWA) by incorporating binary search techniques. Central to this approach is the `get_query_result` function, which executes SQL injection queries tailored with specific table and column names, a target username, and a dynamically calculated midpoint value. This function's results, interpreted as `True` for successful conditions and `False` otherwise, facilitate the binary search strategy, drastically cutting down the query count needed for determining the password hash's length over traditional linear search methods.

Further refinement is seen in character extraction for the password hash. By leveraging the `ASCII(SUBSTR())` function, the script conducts a binary search on ASCII values to pinpoint each hash character efficiently. This method contrasts sharply with the exhaustive linear search, offering a notable reduction in queries by halving the search space until the correct character is identified. This dual application of binary search—first, to ascertain the hash length and then to decode its characters—marks a significant leap in optimizing SQL injection efforts, ensuring a faster and more resource-effective breach process.

## Disclaimer

The tools and scripts provided in this repository are made available for educational purposes only and are intended to be used for testing and protecting systems with the consent of the owners. The author does not take any responsibility for the misuse of these tools. It is the end user's responsibility to obey all applicable local, state, national, and international laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Under no circumstances should this tool be used for malicious purposes. The author of this tool advocates for the responsible and ethical use of security tools. Please use this tool responsibly and ethically, ensuring that you have proper authorization before engaging any system with the techniques demonstrated by this project.

## Acknowledgments

This project is based on the original [blind_sqli project](https://github.com/StackZeroSec/dvwa/tree/main/blind_sqli) by [StackZeroSec](https://github.com/StackZeroSec). We thank them for their work and contributions to the security community.

## Features

- **Efficient Data Extraction**: Implements binary search algorithms to determine the length of data fields and character values, significantly reducing the number of queries required compared to linear search methods.
- **Targeted SQL Injection**: Uses precise SQL injection techniques tailored to extract specific information such as database names, table contents, and password hashes.
- **Interactive Exploration**: Allows users to interactively specify targets for exploration, enhancing the flexibility and focus of the attack.
- **Advanced Query Construction**: Dynamically constructs SQL queries based on user input and binary search outcomes, optimizing the process for efficiency and effectiveness.
- **Security Level Adjustment**: Capable of adjusting the security settings of the target application (DVWA) to test different levels of SQL injection defenses.

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
    sudo pip install requests beautifulsoup4 enum
    ```
    
2. **Download Scripts**: Clone or download the scripts from the project repository to your local machine.
3. **Configure DVWA**: Set up DVWA to run locally or access a remote instance. Ensure it is configured to be vulnerable to SQL Injection. Alternatively, you can follow the instructions below for DVWA hosted on Try Hack Me.

## DVWA Setup (THM)

1. **Setup VPN connection to DVWA machine in THM.**
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
    python3 restricted_blind_sqli.py
    ```
    
    - Enter the IP address of the DVWA machine when prompted to execute the SQL injection.
4. **Cracking the Obtained Password Hash:**
    - Once you've successfully extracted the password hash for a user, navigate to [CrackStation's website](https://crackstation.net/) and enter the obtained password hash into the textbox.
    - CrackStation will process the hash and, if possible, return the plaintext password associated with that hash. This process works by looking up the hash in a large database of pre-computed hash values and their corresponding plaintext counterparts.

## How It Works

The script operates in several key phases to exploit Blind SQL Injection vulnerabilities:

1. **Session Initialization**: Establishes a session with the Damn Vulnerable Web Application (DVWA), handling login and CSRF token management.
2. **Setting Security Level**: Adjusts the security level of DVWA to the lowest setting to facilitate testing and manipulation.
3. **Binary Search for Data Length**: Employs binary search techniques to efficiently determine the length of the database name, significantly reducing the number of required queries.
4. **Character Extraction Using Binary Search**: Further applies binary search to the ASCII values to pinpoint each character of the database name, table names, and ultimately, user password hashes.
5. **Interactive User Input**: Allows users to specify particular tables and columns for targeted data extraction, providing control over the scope of the SQL injection attack.
6. **Data Retrieval**: Executes crafted SQL queries to extract and display sensitive information based on the findings from binary searches, such as the names and contents of database tables and user credentials.
7. **Query Optimization and Feedback**: Throughout the process, the script provides real-time feedback on the progress of the attack and optimizes SQL queries to minimize the database server's load and response time.

The combination of binary search with interactive and dynamic SQL injection makes this script highly effective and efficient for educational and testing purposes in environments like DVWA.

## Output Example

```bash
$ python3 restricted_blind_sqli.py
Enter the DVWA server IP address: 10.10.x.x
[+] Length of the database name is 4
Queries made to find database name length: 4

[+] Database name discovered: dvwa
Queries made to find database name: 46

[+] Number of tables in the database: 2
Queries made to find number of tables: 1

         guestbook
         users
Queries made to find table names: 287

Enter the name of the table to analyze: users
[+] Number of columns in 'users': 8
Queries made to find number of columns: 7

[!] Attempting to accelerate the process. Press CTRL+C when you find the target columns.
         userid
         firstname
         lastname
         user
         password
^C
User discovery halted!
Enter the username column name: user
Enter the password hash column name: password
[!] To further speed up the process, press CTRL+C when you find the target user
| __________ admin
^C
User discovery halted!
Enter the target username for password hash extraction: admin
[+] Length of the password hash for 'admin': 32
Queries made to find password hash length: 1

[+] Password hash for 'admin': 5f4dcc3b5aa765d61d8327deb882cf99
Queries made to extract password hash: 32
```
![Crackstation](/images/CrackStation_results.png)

## Contributing

If you have an idea for an improvement or if you're interested in collaborating, you are welcome to contribute. Please feel free to open an issue or submit a pull request.

## License

This project is licensed under the GNU General Public (GPL) License - see the [LICENSE](https://github.com/CyberWolfByte/dvwa/blob/main/LICENSE) file for details.
