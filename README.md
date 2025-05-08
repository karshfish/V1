# Task Management API

This project is a RESTful API for managing tasks. It provides endpoints for user authentication, session management, and CRUD (Create, Read, Update, Delete) operations on tasks.

## Features

- **User Management**:
  - User registration with secure password hashing.
  - Authentication using access tokens.

- **Session Management**:
  - Login and logout functionality.
  - Token-based authentication with access and refresh tokens.

- **Task Management**:
  - Create, retrieve, update, and delete tasks.
  - Filter tasks by completion status.
  - Paginate tasks for efficient data retrieval.

- **Database Interaction**:
  - Uses MySQL for storing user and task data.
  - Secure database queries using prepared statements.

- **Error Handling**:
  - Standardized API responses with HTTP status codes, success flags, and error messages.

## Prerequisites

- PHP 7.4 or higher
- MySQL database
- Composer (optional, for dependency management)
- XAMPP or any local server environment

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/karshfish/V1
   cd task-management-api
   Set up the database:

2. Import the database.sql file into your MySQL database.
Update the database connection details in Controller/DB.php.
Start your local server (e.g., XAMPP) and place the project in the htdocs directory.

Access the API via http://localhost/v1.

API Endpoints
User Endpoints
POST /users: Register a new user.
Request Body:
{
  "username": "example",
  "password": "password123",
  "fullName": "John Doe"
}
Session Endpoints
. POST /sessions: Login and create a session.

Request Body:

{
  "username": "example",
  "password": "password123"
}
PATCH /sessions/{session<vscode_annotation details='%5B%7B%22title%22%3A%22hardcoded-credentials%22%2C%22description%22%3A%22Embedding%20credentials%20in%20source%20code%20risks%20unauthorized%20access%22%7D%5D'>id</vscode_annotation>}: Refresh tokens.

Task Endpoints
GET /tasks: Retrieve all tasks for the authenticated user.
GET /tasks/{taskid}: Retrieve a specific task by ID.
POST /tasks: Create a new task.
Request Body:
{
  "title": "New Task",
  "description": "Task description",
  "deadline": "10/05/2025 15:00",
  "completed": "N"
}
License
This project is licensed under the MIT License.

