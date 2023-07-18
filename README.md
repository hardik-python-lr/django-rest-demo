# Visitor Management

### Technology Used
 
- Python 3.10.9
- Django
- Rest API
- Django Rest Framework
- PostgreSQL
- Swagger (for API documentation)

### Steps to setup the project

    1) Clone the GIT repo
    2) Create virtual environment and install requirement txt file  "pip3 install -r requirement.txt"
    3) Create .env file and replace the details with actual details by referencing attached .env-sample file
    4) Run makemigrations and migrate commands
    5) Run runserver command
    6) Go to "localhost:8000/swagger" and access the endpoint "/users/super-admin-setup/" under users section to create the first user

### Example Modules

1) User module
    - User CRUD operation management with different roles so that API can be allowed to certain ROLE
    - Dropdown and List-Filter APIs
    - ROLE Base linking i.e OrganizationAdmin linking, EstablishmentAdmin linking, and EstablishmentGuard linking
    - Custom Hybrid OTP based login of user

2) Organization module
    - CRUD operation of organization model and Dropdown and List-Filter APIs

3) Establishment module
    - CRUD operation of establishment model and Dropdown and List-Filter APIs

4) Building module
    - CRUD operation of building model and Dropdown and List-Filter APIs

5) Flat module
    - CRUD operation of flat model and Dropdown and List-Filter APIs

6) Custom Attendance module
    - Dynamic capturing of attendance with geo mapping (restriction of false location) 
