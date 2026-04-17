# Role-based-authtentication

A Flask web application for library user management using **Role-Based Access Control (RBAC)**.  
This project demonstrates how different user roles can be assigned different permissions within a simple library system.

## Overview

This application supports multiple user roles and restricts access to actions based on those roles.  
User data is stored in a simple JSON file, making the project lightweight and easy to understand for learning and development purposes.

The system includes:

- User login
- User provisioning / account creation
- Role-based access checks
- Admin user management
- Placeholder routes for library actions such as adding books, deleting books, borrowing, returning, and catalog searching

## Roles

The application currently supports these roles:

- **Library Administrator**
- **Librarian**
- **Library Member**

## Permissions by Role

### Library Administrator
- Manage users
- Add books
- Delete books
- Borrow books
- Return books
- Search catalog

### Librarian
- Add books
- Delete books
- Search catalog

### Library Member
- Borrow books
- Return books
- Search catalog

## Features

- Built with **Flask**
- Uses **role-based authorization**
- Stores user data in **JSON**
- Loads environment variables using **python-dotenv**
- Supports basic login and session handling
- Includes templates for:
  - Home page
  - Login page
  - Dashboard
  - User management
  - Provision page
  - Add/remove user pages

## Tech Stack

- Python
- Flask
- HTML
- CSS
- JavaScript
- JSON for lightweight data storage

## Project Structure

```bash
Role-based-authtentication/
│
├── app.py
├── requirements.txt
├── .env
├── data/
│   └── users.json
├── static/
└── templates/
    ├── base.html
    ├── home.html
    ├── login.html
    ├── dashboard.html
    ├── manage_users.html
    ├── provision.html
    ├── user_add.html
    ├── user_remove.html
    └── action.html
```

## How to Run on Your System

### 1. Clone the repository
```bash
git clone https://github.com/pateltaanish/Role-based-authtentication.git
cd Role-based-authtentication
```

### 2. Create a virtual environment

#### Windows PowerShell
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

#### Windows Command Prompt
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

#### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Create a `.env` file
Create a file named `.env` in the root folder and add:

```env
SECRET_KEY=your-secret-key-here
```

### 5. Run the app
```bash
python app.py
```

### 6. Open in browser
Go to:

```text
http://127.0.0.1:5000
```

### 7. Create or log into an account
- If a user already exists in `data/users.json`, log in normally
- Otherwise, go to `/provision` to create an account

Example:

```text
http://127.0.0.1:5000/provision
```



