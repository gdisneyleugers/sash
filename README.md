sash
====

Secure again Shell:

Policy driven shell with auditable logs.

Installation: 
    
    pip install pyYAML paramiko

To run:

    python shell.py



whitelist: 

        This policy is the threshold policy, the default threshold is 3 before disconnect. 
    
blacklist:

        This policy is the blacklist policy, the default threshold is 0 before disconnect.
to do session based alteration of policy:

        alter.list: [whitelist|blacklist] 
        policy.list: list policy
        threshold: shows current whitelist threshold.
        threshold.set: sets threshold for whitelist.
        risk: shows current session threshold
        risk.reset: resets risk

Any alteration of session policy results in logging.

To access the ssh shell:
        
        ssh.shell
