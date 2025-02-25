# Python Database Project

## Description

This project is a Python application that interacts with a PostgreSQL database. It uses FastAPI as a web framework (`app.py`) and SQLAlchemy for database interactions (`database.py`, `models.py`). The project includes testing files (`db_test.py`, `test.py`) to ensure functionality.

## Installation

1.  **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

    This will install the following packages:

    *   FastAPI==0.110.0
    *   SQLAlchemy==2.0.29
    *   psycopg2-binary==2.9.9
    *   python-jose[cryptography]==3.3.0
    *   passlib==1.7.4
    *   pandas==2.2.1
    *   python-multipart==0.0.9
    *   uvicorn==0.29.0

2.  **Install PostgreSQL:**

    1.  Go to the official PostgreSQL download page: [https://www.postgresql.org/download/]
    2.  Select your operating system and follow the instructions to download the appropriate installer.
    3.  Run the downloaded installer and follow the on-screen instructions. Make sure to note down the database username, password, and port during the installation process.

3.  **Configure Database:**

    Update the database connection details in `database.py` with the credentials you set during the PostgreSQL installation.

## Usage

To run the application, execute the following command in your terminal:

```bash
python app.py
```

## Testing

To run database related tests:

```bash
python db_test.py
```

To run other tests:

```bash
python test.py
