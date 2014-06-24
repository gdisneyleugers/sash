#!/bin/env python
__author__ = 'gregorydisney'
__name__ = '__main__'
import os
import time
import readline
import getpass
from os import system as sys

import paramiko
import yaml
from yaml import load as config


logger = file('shell.log', 'a')
logger.write("Shell Started" + " @ " + time.asctime() + " By: " + getpass.getuser() + "\n")


class systemCMD:
    blcnf = config(file('blacklist.yaml', 'r'))
    whcnf = config(file('whitelist.yaml', 'r'))
    cmdcnf = config(file('cmd.yaml', 'r'))
    cmdlist = ''.join(cmdcnf)
    level = 0
    risk = level
    rip = 3
    tab = readline.parse_and_bind('tab: complete')
    readline.insert_text(cmdlist)
    readline.set_startup_hook()
    while True:
        timer = time.asctime()
        if level == rip:
            print("Insider threat detected")
            logger.write("Insider Threat Detected: " + " @ " + timer + " By: " + getpass.getuser() + '\n')
            quit()

        cmd = raw_input('Secure-Shell=> ')
        a = "sh: " + cmd + ": " + "command not found"
        if a:
            import shell
        tab = readline.parse_and_bind('tab: complete')
        readline.insert_text(cmdlist)
        ecmd = cmd + ':'
        for i, elem in enumerate(blcnf):
            if cmd in elem:
                print("Not Allowed cmd: " + elem + " @ " + timer + " By: " + getpass.getuser())
                logger.write("blacklist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                level = 3
                quit()
                logger.close()
        for i, elem in enumerate(whcnf):
            if cmd in elem:
                print("Allowed but logged: " + elem + "\n" + timer + " By: " + getpass.getuser() + '\n')
                logger.write("whitelist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                risk = level + 1
                level = risk
        if cmd == 'chdir':
            g = raw_input("Dir: ")
            os.chdir(g)
        if cmd in 'cd':
            g = raw_input("Dir: ")
            os.chdir(g)
        if cmd == 'exit':
            print("Exiting\n")
            quit()
            logger.write("whitelist cmd: " + cmd + " @ " + timer + " By: " + getpass.getuser() + '\n')
            logger.close()
        if cmd == 'risk':
            while True:
                print "Risk: ", level, "\n"
                break
                shell
        if cmd == 'risk.reset':
            while True:
                print "Reseting Risk: "
                print "Current Risk: ", level, "\n"
                level = 0
                print "New Risk: ", level, "\n"
                logger.write("Risk reset: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                break
                shell
        if cmd == 'threshold':
            while True:
                print "Threshold: ", rip, "\n"
                break
        if cmd == 'threshold.set':
            while True:
                th = raw_input("Threshold: ")
                print "Current threshold: ", rip, "\n"
                rip = th
                print "New threshold: ", rip, "\n"
                print("Reloading shell")
                logger.write("Threshold set: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                break
                shell
        if cmd == 'ssh.shell':
            client = paramiko.SSHClient()
            host = raw_input("Host: ")
            SSH_PORT = input("Port: ")
            usr = raw_input("User: ")
            if not usr:
                user = getpass.getuser()
            pwd = getpass.getpass("Password: ")
            client.load_system_host_keys()
            print "Connecting to " + host
            logger.write("SSH Shell Started" + " @ " + time.asctime() + " By: " + getpass.getuser() + " as " + usr + "@" + host + "\n")
            while True:
                level = 0
                rip = 3
                level = risk
                timer = time.asctime()
                try:
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    cc = client.connect(host, port=SSH_PORT, username=usr, password=pwd)
                except paramiko.ssh_exception.AuthenticationException:
                    print "Auth Error"
                    logger.write("Auth Error: " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + "\n")
                    import shell
                except paramiko.ssh_exception.SSHException:
                    print "Protocol Error"
                    logger.write("Protocol Error: " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + "\n")
                    import shell
                except paramiko.transport:
                    print "General Error"
                    logger.write("Protocol Error: " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + "\n")
                    import shell
                cmd = raw_input("Secure-SSH-Shell=> ")
                if level == rip:
                    print("Insider threat detected")
                    logger.write("Insider Threat Detected: " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + '\n')
                    import shell
                    break
                for i, elem in enumerate(blcnf):
                    if cmd in elem:
                        print("Not Allowed cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + " as " + usr + "@" + host + "\n")
                        logger.write("ssh blacklist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + " as "+ usr + "@" + host + '\n')
                        level = 3
                        logger.close()
                        import shell
                for i, elem in enumerate(whcnf):
                    if cmd in elem:
                        print("Allowed but logged: " + elem + "\n" + timer + " By " + getpass.getuser() + " as " + usr + "@" + host + '\n')
                        logger.write("ssh whitelist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + " as " + usr + "@" + host + '\n')
                        risk = level + 1
                        level = risk
                if cmd == 'exit':
                    print("Exiting\n")
                    logger.write("Exiting: " + cmd + " @ " + timer + " By: " + getpass.getuser() + '\n')
                    break
                stdin, stdout, stderr = client.exec_command(cmd)
                a = stdout.readlines()
                print ''.join(a)
                with open('sshcmd.yaml', 'a') as outfile:
                    combo = [cmd, a]
                    outfile.write(yaml.dump(combo, default_flow_style=True))
                    outfile.close()
                client.close()
        if cmd in 'print':
            print(cmd)
        if cmd == 'time.now':
            print(timer)
        if cmd == 'user.name':
            print getpass.getuser()
        if cmd == 'alter.list':
            readline.add_history(cmd)
            while True:
                a = raw_input("whitelist or blacklist: ")
                if a == 'blacklist':
                    blcmd = raw_input("Cmd to Blacklist: ")
                    print("Blacklisting for this session => " + blcmd)
                    d = [blcmd, blcnf]
                    blcnf = d
                if a == 'whitelist':
                    whcmd = raw_input("Cmd to whitelist: ")
                    print("whitelisting for this session => " + whcmd)
                    b = [whcmd, whcnf]
                    whcnf = b
                break
                shell
        if cmd == 'policy.list':
            readline.add_history(cmd)
            print "Whitelist:", whcnf
            print "Blacklist:", blcnf
        if cmd == ' ':
            print "Blank command detected"
        if cmd == a:
            print "\n"
        elif cmd:
            try:
                error = sys(cmd)
                errorseq = error > 0
            except a:
                print "\n"
                import shell
                print "\n"
            except OSError:
                print "\n"
                import shell
                print "\n"
            if errorseq:
                    print "Error Logged"
                    logger.write("Error: " + a + " @ " + timer + " By: " + getpass.getuser() + '\n')
    if __name__ == '__main__':
       import shell