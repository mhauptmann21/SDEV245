""" 
Basic Authentication & Role-Based Acess Control Demo 

This demo simulates a simple authentication system to demonstrate
confidentiality in a software application. It includes user login,
role-based access control, and protected actions based on user roles.

"""

# Users
users = {
    "alice": {"password": "wonderland", "role": "admin"},
    "bob": {"password": "builder", "role": "user"}
}

data = {
    "sensitive_data": "Top Secret Information",
    "user_data": "General User Information"
}

# Protected Actions
def admin_action(username):
    print(f"[ADMIN ACTION] Welcome, {username}! You can now view sensitive data.")
    admin_panel()

def user_action(username):
    print(f"[USER ACTION] Welcome, {username}! You are now viewing your dashboard.")
    user_dashboard()

# Access Control
def perform_action(username):

    if users[username]['role'] == "admin":
        admin_action(username)
    elif users[username]['role'] == "user":
        user_action(username)
    else:
        print("Access Denied: You do not have permission to perform this action.")

# Login Simulation
def main():
    print("=== Login ===")
    username = input("enter your username: ")
    password = input("enter your password: ")

    if username in users and users[username]["password"] == password:
        print(f"Login successful. Role: {users[username]['role']}")
        perform_action(username)
    else:
        print("Login failed: User not found.")

# Admin Panel
def admin_panel():
    print("Admin Panel:")
    print("1. View Users")
    print("2. View Sensitive Data")
    print("3. Update Sensitive Data")
    print("4. Logout")
    selction = input("Select an option (1-4): ")

    if selction == '1':
        print("User List:")
        for user in users:
            print(f"- {user} (Role: {users[user]['role']})")
    elif selction == '2':
        view_sensitive_data()
    elif selction == '3':
        update_sensitive_data()
    elif selction == '4':
        print("Logging out...")
    else:
        print("Invalid selection. Please try again.")
        admin_panel()

# User Dashboard
def user_dashboard():
    print("User Dashboard:")
    print("1. Settings")
    print("2. Change Password")
    print("3. Logout")
    selction = input("Select an option (1-3): ")

    if selction == '1':
        print("Settings:")
        print("Coming soon...")
    elif selction == '2':
        print("Coming soon...")
    elif selction == '3':
        print("Logging out...")
    else:
        print("Invalid selection. Please try again.")
        user_dashboard()

# Update Sensitive Data
def update_sensitive_data():
    new_data = input("ENTER UPDATED SENSITIVE DATA (enter 'ZZZ' to exit): ")
    if new_data != 'ZZZ':
        data["sensitive_data"] = new_data
        print("Sensitive data updated.")

# View Sensitive Data
def view_sensitive_data():
    print(f"Sensitive Data: {data['sensitive_data']}")


# Run App
if __name__ == "__main__":
    main()