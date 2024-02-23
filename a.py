import mysql.connector

def create_database():
    try:
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="password"
        )

        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()

        # Execute a MySQL query to create the database
        cursor.execute("CREATE DATABASE IF NOT EXISTS iss_proj")

        print("Database created successfully")

    except mysql.connector.Error as error:
        print("Error while connecting to MySQL", error)

    finally:
        if (connection.is_connected()):
            # Close cursor and connection
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

def create_table():
    try:
        # Connect to the created database
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="password",
            database="iss_proj"
        )

        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()

        # Execute a MySQL query to create a table for storing user login information
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
                            username VARCHAR(255) PRIMARY KEY,
                            name VARCHAR(255) NOT NULL,
                            email VARCHAR(255) NOT NULL UNIQUE,
                            password VARCHAR(255) NOT NULL
                        )""")

        print("Table created successfully")

    except mysql.connector.Error as error:
        print("Error while connecting to MySQL", error)

    finally:
        if (connection.is_connected()):
            # Close cursor and connection
            cursor.close()
            connection.close()
            print("MySQL connection is closed")
            
def print_table_contents(table_name):
    try:
        # MySQL Configuration
        db_connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="password",
            database="iss_proj"
        )

        # Create a cursor object
        cursor = db_connection.cursor()

        # Execute the query to select all rows from the table
        cursor.execute("SELECT * FROM {}".format(table_name))

        # Fetch all rows
        rows = cursor.fetchall()

        # Print column names
        column_names = [i[0] for i in cursor.description]
        print("\t".join(column_names))

        # Print each row
        for row in rows:
            print("\t".join(str(cell) for cell in row))
        
        # Close cursor and database connection
        cursor.close()
        db_connection.close()

    except mysql.connector.Error as error:
        print("Error reading data from MySQL table:", error)


def main():
    create_database()
    create_table()
    print_table_contents('users')

if __name__ == "__main__":
    main()