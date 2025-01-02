import streamlit as st 
import mysql.connector
import hashlib
import pandas as pd
import smtplib
from email.message import EmailMessage
import io

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="9698",
        database="employee_management"
    )

# Retrieve email credentials from the database
def get_email_credentials():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT sender_email, app_password FROM email_credentials LIMIT 1")
        credentials = cursor.fetchone()
        return credentials['sender_email'], credentials['app_password']
    except Exception as e:
        st.error(f"Error retrieving email credentials: {e}")
        return None, None
    finally:
        conn.close()

# Hashing passwords for security
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Login function
def authenticate_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT role FROM user_accounts WHERE username=%s AND password=%s"
    hashed_password = hash_password(password)
    cursor.execute(query, (username, hashed_password))
    result = cursor.fetchone()
    conn.close()
    return result  # Returns role if credentials are correct, None otherwise

# Email notification function
def send_email(employee_name, status, comment, recipients):
    sender_email, app_password = get_email_credentials()
    if not sender_email or not app_password:
        st.error("Failed to send email. Missing email credentials.")
        return

    subject = f"Employee {employee_name} - Status Update: {status}"
    body = f"""
    Employee Name: {employee_name}
    Status: {status}
    Comment: {comment}
    """
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = ", ".join(recipients)
        msg.set_content(body)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)

        st.info(f"Email notification sent successfully to {', '.join(recipients)}!")
    except Exception as e:
        st.error(f"Failed to send email: {e}")

# Streamlit app
st.title("Employee Status Management")

# Login page
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.search_results = None  # To store search results
    st.session_state.selected_status = "Green"  # Default RAG status
    st.session_state.comment = ""  # Default comment

if not st.session_state.logged_in:
    st.header("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        role = authenticate_user(username, password)
        if role:
            st.session_state.logged_in = True
            st.session_state.role = role[0]
            st.success(f"Logged in as {role[0]}")
        else:
            st.error("Invalid username or password")
else:
    st.sidebar.write(f"Logged in as: {st.session_state.role}")
    st.sidebar.button("Logout", on_click=lambda: st.session_state.update({"logged_in": False, "role": None, "search_results": None}))

# Admin functionality
if st.session_state.logged_in and st.session_state.role == "admin":
    st.header("Admin Dashboard")

    # Tabs for Admin
    tab1, tab2, tab3 = st.tabs(["User Management", "Dataset Management", "Reports"])

    # Tab 1: User Management
    with tab1:
        st.subheader("Manage Users")

        # Add New User
        st.write("### Add New User")
        new_username = st.text_input("Username", key="add_user_username")
        new_password = st.text_input("Password", type="password", key="add_user_password")
        new_role = st.selectbox("Role", ["admin", "user"], key="add_user_role")
        if st.button("Add User", key="add_user_button"):
            if new_username and new_password:
                conn = get_db_connection()
                cursor = conn.cursor()
                try:
                    hashed_password = hash_password(new_password)
                    query = "INSERT INTO user_accounts (username, password, role) VALUES (%s, %s, %s)"
                    cursor.execute(query, (new_username, hashed_password, new_role))
                    conn.commit()
                    st.success(f"User '{new_username}' added successfully!")
                except mysql.connector.Error as err:
                    st.error(f"Error: {err}")
                finally:
                    conn.close()
            else:
                st.warning("Please provide all details.")

        # Remove User
        st.write("### Remove User")
        remove_username = st.text_input("Username to Remove", key="remove_user_username")
        if st.button("Remove User", key="remove_user_button"):
            if remove_username:
                conn = get_db_connection()
                cursor = conn.cursor()
                try:
                    query = "DELETE FROM user_accounts WHERE username=%s"
                    cursor.execute(query, (remove_username,))
                    if cursor.rowcount > 0:
                        conn.commit()
                        st.success(f"User '{remove_username}' removed successfully!")
                    else:
                        st.warning("User not found.")
                except mysql.connector.Error as err:
                    st.error(f"Error: {err}")
                finally:
                    conn.close()

    # Tab 2: Dataset Management
    with tab2:
        st.subheader("Manage Employee Dataset")

        # Upload Dataset
        st.write("### Upload Dataset")
        uploaded_file = st.file_uploader("Upload an Excel file", type=["xlsx"], key="upload_dataset")
        if st.button("Upload Dataset", key="upload_dataset_button") and uploaded_file:
            try:
                # Read Excel file
                df = pd.read_excel(uploaded_file)
                conn = get_db_connection()
                cursor = conn.cursor()
                # Insert data into employees table
                for _, row in df.iterrows():
                    query = """
                    INSERT INTO employees (id, name, designation, manager_id)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE name=VALUES(name), designation=VALUES(designation), manager_id=VALUES(manager_id)
                    """
                    cursor.execute(query, (row['id'], row['name'], row['designation'], row['manager_id']))
                conn.commit()
                st.success("Dataset uploaded successfully!")
            except Exception as e:
                st.error(f"Error uploading dataset: {e}")
            finally:
                conn.close()

        # Delete Dataset
        st.write("### Delete Dataset")
        if st.button("Delete All Employee Data", key="delete_dataset_button"):
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                query = "DELETE FROM employees"
                cursor.execute(query)
                conn.commit()
                st.success("All employee data deleted successfully!")
            except mysql.connector.Error as err:
                st.error(f"Error: {err}")
            finally:
                conn.close()

    # Tab 3: Reports
    with tab3:
        st.subheader("Generate Reports")

        # Filter by RAG status
        rag_status = st.selectbox("Select RAG Status", ["All", "Green", "Amber", "Red"], key="report_rag_status")

        # Filter by date range
        start_date = st.date_input("Start Date", key="report_start_date")
        end_date = st.date_input("End Date", key="report_end_date")

        if st.button("Generate Report", key="generate_report_button"):
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            try:
                query = "SELECT * FROM employee_status WHERE 1=1"

                # Apply RAG status filter
                if rag_status != "All":
                    query += " AND status = %s"

                # Apply date range filter
                query += " AND DATE(timestamp) BETWEEN %s AND %s"

                params = ()
                if rag_status != "All":
                    params += (rag_status,)
                params += (start_date, end_date)

                cursor.execute(query, params)
                report_data = cursor.fetchall()

                if report_data:
                    # Convert to DataFrame
                    df = pd.DataFrame(report_data)
                    st.write("### Report")
                    st.dataframe(df)

                    # Download as CSV
                    csv = df.to_csv(index=False)
                    st.download_button("Download CSV", data=csv, file_name="report.csv", mime="text/csv")
                else:
                    st.warning("No data found for the selected filters.")
            except mysql.connector.Error as err:
                st.error(f"Error: {err}")
            finally:
                conn.close()

# User functionality
if st.session_state.logged_in and st.session_state.role == "user":
    st.header("Employee Management")

    # Search and Update Employee RAG Status
    st.subheader("Search and Update Employee RAG Status")

    search_option = st.selectbox("Search By", ["ID", "Name"], key="search_option")
    search_query = st.text_input("Enter ID or Name", key="search_query")
    if st.button("Search", key="search_button"):
        if search_query:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            try:
                if search_option == "ID":
                    query = "SELECT * FROM employees WHERE id = %s"
                    cursor.execute(query, (search_query,))
                else:
                    query = "SELECT * FROM employees WHERE name LIKE %s"
                    cursor.execute(query, (f"%{search_query}%",))
                st.session_state.search_results = cursor.fetchall()
                if st.session_state.search_results:
                    st.write("### Employee Details")
                    st.dataframe(st.session_state.search_results)
                else:
                    st.warning("No employee found.")
            except mysql.connector.Error as err:
                st.error(f"Error: {err}")
            finally:
                conn.close()

    # Display and Update RAG Status if search results exist
    if st.session_state.search_results:
        emp_id = st.session_state.search_results[0]['id']
        emp_name = st.session_state.search_results[0]['name']  # Retrieve the name

        st.session_state.selected_status = st.radio(
            "Select RAG Status", 
            ["Green", "Amber", "Red"], 
            index=["Green", "Amber", "Red"].index(st.session_state.selected_status),
            key="rag_status"
        )
        st.session_state.comment = st.text_area(
            "Comment", 
            value=st.session_state.comment,
            key="rag_comment"
        )
        if st.button("Update Status", key="update_status_button"):
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Update employee status in the database
                query = """
                INSERT INTO employee_status (employee_id, name, status, comment, timestamp)
                VALUES (%s, %s, %s, %s, NOW())
                """
                cursor.execute(query, (emp_id, emp_name, st.session_state.selected_status, st.session_state.comment))
                conn.commit()

                # Fetch email recipients for the selected status
                query_recipients = "SELECT email FROM email_recipients WHERE status = %s"
                cursor.execute(query_recipients, (st.session_state.selected_status,))
                recipients = [row[0] for row in cursor.fetchall()]

                # Send email notification if there are recipients
                if recipients:
                    send_email(
                        employee_name=emp_name,
                        status=st.session_state.selected_status,
                        comment=st.session_state.comment,
                        recipients=recipients
                    )
                else:
                    st.warning("No email recipients found for the selected status.")

                st.success(f"Updated status for Employee ID {emp_id} to {st.session_state.selected_status}.")
            except mysql.connector.Error as err:
                st.error(f"Error: {err}")
            finally:
                conn.close()

    # Employee Status History
    st.subheader("View Employee Status History")
    history_query = st.text_input("Enter Employee ID to View History", key="history_query")
    if st.button("View History", key="view_history_button"):
        if history_query:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            try:
                query = "SELECT * FROM employee_status WHERE employee_id = %s ORDER BY timestamp DESC"
                cursor.execute(query, (history_query,))
                history_results = cursor.fetchall()
                if history_results:
                    st.write("### Status History")
                    st.dataframe(history_results)
                else:
                    st.warning("No history found for this employee.")
            except mysql.connector.Error as err:
                st.error(f"Error: {err}")
            finally:
                conn.close()
