# IamTheWatcher

Python libraries for AWS IAM security audit.


Also includes two functions forked from Rhino Security research on [aws privilege escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) 

##  Use

### Requirements

Have sso user with SecurityAudit (or ReadOnly for iam) privileges to allow scan.

Must to be logged. Before start execute

    aws sso login 

An example of use is provided in main function that:

* Retrieve all accounts
* Retrieve all users & roles in these accounts
* Analyze each user/role for possible privilege escalation
* Generate output file with the results for each account

So, you just need to execute:

    python3 ./IamTheWatcher.py

Enjoy.


