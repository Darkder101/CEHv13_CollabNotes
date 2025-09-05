# SQL Injection Concepts

## What is SQL Injection?

SQL injection (SQLi) is a code injection technique that exploits security vulnerabilities in an application's software by inserting malicious SQL statements into entry fields for execution. It allows attackers to manipulate database queries to:

- Access unauthorized data
- Modify or delete database records
- Bypass authentication mechanisms
- Execute administrative operations on the database
- In some cases, issue commands to the operating system

### SQL Injection Definition
SQL injection occurs when user input is improperly filtered for string literal escape characters embedded in SQL statements or when user input is not strongly typed, allowing malicious code execution.

## Why Bother About SQL Injection?

### Critical Security Risks

1. **Data Breach**: Unauthorized access to sensitive information including:
   - User credentials
   - Personal information (PII)
   - Financial records
   - Business-critical data

2. **Data Manipulation**: Attackers can:
   - Modify existing records
   - Insert malicious data
   - Delete entire databases
   - Corrupt data integrity

3. **Authentication Bypass**: 
   - Login without valid credentials
   - Escalate user privileges
   - Impersonate legitimate users

4. **System Compromise**:
   - Execute system commands
   - Install backdoors
   - Lateral movement within networks

### Business Impact

- **Financial Loss**: Direct losses from data breaches, regulatory fines
- **Reputation Damage**: Loss of customer trust and brand value
- **Compliance Violations**: GDPR, HIPAA, PCI-DSS penalties
- **Operational Disruption**: System downtime and recovery costs

## SQL Injection and Server-Side Technologies

### Vulnerable Technologies

SQL injection affects various server-side technologies and database systems:

#### Web Application Frameworks
- **ASP.NET**: Vulnerable when using dynamic SQL queries
- **PHP**: Common with mysql_query() and inadequate input sanitization
- **Java/JSP**: Susceptible with JDBC and dynamic query building
- **Python**: Flask, Django applications with raw SQL queries
- **Ruby on Rails**: ActiveRecord with raw SQL execution
- **Node.js**: Applications using database drivers without parameterization

#### Database Management Systems
- **MySQL**: Most commonly targeted in web applications
- **Microsoft SQL Server**: Enterprise environments, stored procedures
- **PostgreSQL**: Advanced features can be exploited
- **Oracle**: Complex enterprise applications
- **SQLite**: Mobile and embedded applications
- **MongoDB**: NoSQL injection variants

#### Application Types
- **Web Applications**: E-commerce, CMS, forums
- **Mobile Apps**: Backend APIs and databases
- **Desktop Applications**: Client-server architectures
- **Web Services**: REST APIs, SOAP services

## Understanding HTTP POST Requests

### HTTP POST Method Fundamentals

HTTP POST is used to submit data to be processed to a specified resource, commonly used in:
- Form submissions
- User authentication
- Data uploads
- API interactions

### POST Request Structure

```http
POST /login.php HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

username=admin&password=secretpass
```

### POST Parameters in SQL Injection

POST parameters are often used in SQL queries without proper sanitization:

```php
// Vulnerable PHP code
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

### POST vs GET in SQL Injection Context

| Aspect | POST | GET |
|--------|------|-----|
| **Parameter Location** | Request body | URL query string |
| **Visibility** | Hidden from URL | Visible in URL/logs |
| **Length Limit** | Large payloads possible | URL length restrictions |
| **Caching** | Not cached by default | May be cached |
| **Detection** | Requires body inspection | Easily spotted in logs |

## Understanding Normal SQL Query

### Basic SQL Query Structure

```sql
SELECT column1, column2 FROM table_name WHERE condition;
```

### Normal Authentication Query

A typical login verification query:

```sql
SELECT user_id, username, role 
FROM users 
WHERE username = 'admin' AND password = 'secretpass123';
```

### Query Components

1. **SELECT Clause**: Specifies columns to retrieve
2. **FROM Clause**: Identifies target table(s)
3. **WHERE Clause**: Defines filtering conditions
4. **AND/OR Operators**: Combine multiple conditions

### Normal Query Flow

1. **User Input**: Username and password entered
2. **Parameter Binding**: Values inserted into query template
3. **Query Execution**: Database processes the complete query
4. **Result Processing**: Application handles returned data
5. **Response Generation**: User sees appropriate result

### Example Normal Queries

```sql
-- User registration
INSERT INTO users (username, email, password) 
VALUES ('john_doe', 'john@email.com', 'hashed_password');

-- Profile update
UPDATE users 
SET email = 'newemail@domain.com' 
WHERE user_id = 123;

-- Data retrieval
SELECT product_name, price 
FROM products 
WHERE category = 'electronics' AND price < 500;
```

## Understanding SQL Injection Query

### Malicious Query Construction

SQL injection manipulates the intended query structure by injecting malicious SQL code:

```sql
-- Intended query
SELECT * FROM users WHERE username = 'admin' AND password = 'password123';

-- Injected query
SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything';
```

### Injection Mechanism

The attacker input `admin'--` transforms the query by:
1. **Closing the string**: Single quote ends the username parameter
2. **Starting comment**: Double dash comments out the password check
3. **Bypassing authentication**: Password validation is ignored

### Common Injection Patterns

#### Authentication Bypass
```sql
-- Original: WHERE username = 'USER_INPUT' AND password = 'PASS_INPUT'
-- Input: ' OR '1'='1'--
-- Result: WHERE username = '' OR '1'='1'--' AND password = 'anything'
```

#### Union-Based Injection
```sql
-- Original: SELECT name FROM products WHERE id = 'USER_INPUT'
-- Input: 1' UNION SELECT username FROM users--
-- Result: Returns product names AND usernames
```

#### Boolean-Based Blind Injection
```sql
-- Original: WHERE id = 'USER_INPUT'
-- Input: 1' AND (SELECT COUNT(*) FROM users) > 5--
-- Result: Reveals information through application responses
```

### Injection Points

SQL injection can occur in various input parameters:

1. **Form Fields**: Login forms, search boxes, contact forms
2. **URL Parameters**: GET request query strings
3. **HTTP Headers**: User-Agent, X-Forwarded-For, Referer
4. **Cookies**: Session tokens and stored values
5. **File Uploads**: Filename parameters, metadata
6. **JSON/XML Data**: API request bodies

### Query Transformation Examples

#### Normal vs Injected Queries

**Product Search - Normal**
```sql
SELECT * FROM products WHERE name LIKE '%laptop%';
```

**Product Search - Injected**
```sql
-- Input: laptop%'; DROP TABLE products;--
SELECT * FROM products WHERE name LIKE '%laptop%'; DROP TABLE products;--%';
```

**Login - Normal**
```sql
SELECT id FROM users WHERE username = 'john' AND password = 'secret123';
```

**Login - Injected**
```sql
-- Input: admin' OR 1=1#
SELECT id FROM users WHERE username = 'admin' OR 1=1#' AND password = 'anything';
```

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **SQL Injection Definition**: Code injection technique exploiting database vulnerabilities
2. **Impact Assessment**: Data breach, authentication bypass, system compromise
3. **Technology Stack**: Understanding vulnerable frameworks and databases
4. **HTTP Methods**: POST vs GET parameter handling in injection context
5. **Query Structure**: Normal SQL syntax vs malicious query manipulation
6. **Business Risk**: Financial, operational, and compliance implications

### Exam Focus Areas
- **Vulnerability Identification**: Recognizing SQL injection points in applications
- **Query Analysis**: Understanding how injection transforms SQL statements
- **Impact Evaluation**: Assessing potential damage from successful attacks
- **Technology Mapping**: Identifying vulnerable server-side technologies
- **HTTP Protocol**: POST/GET parameter injection techniques
- **Database Systems**: Different DBMS-specific injection approaches
- **Risk Assessment**: Business and technical impact evaluation

### Practical Skills
- Identify potential injection points in web applications
- Analyze normal vs malicious SQL query structures  
- Evaluate HTTP request/response for injection indicators
- Recognize vulnerable server-side technology stacks
- Understand the relationship between input validation and SQL injection
- Assess business impact of SQL injection vulnerabilities
