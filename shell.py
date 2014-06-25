#!/bin/env python
__author__ = 'gregorydisney'
__name__ = '__main__'
import os
import time
import readline
import getpass
import socket
from os import system as sys

import paramiko
import yaml
from yaml import load as config


logger = file('shell.log', 'a')
logger.write("Shell Started" + " @ " + time.asctime() + " By: " + getpass.getuser() + "\n")


class SystemCmd:
    def __init__(self):
        __init__ = __name__

    blcnf = config(file('blacklist.yaml', 'r'))
    whcnf = config(file('whitelist.yaml', 'r'))
    cmdcnf = config(file('cmd.yaml', 'r'))
    cmdlist = ''.join(cmdcnf)
    level = 0
    risk = level
    rip = 3
    srisk = rip
    tab = readline.parse_and_bind('tab: complete')
    readline.insert_text(cmdlist)
    readline.set_startup_hook()
    while True:
        try:
            timer = time.asctime()
        except KeyboardInterrupt:
            print "Exiting\n"
            quit()
        if level == rip:
            print "\n"
            print("Warning: Whitelist policy invalidating session\n")
            logger.write("Whitelist policy invalidating session: " + " @ " + timer + " By: " + getpass.getuser() + '\n')
            quit()
        try:
            cmd = raw_input('Secure-Shell=> ')
        except KeyboardInterrupt:
            print "\n"
            print "Exiting \n"
            quit()
        except SystemError:
            print "Exit"
        except SystemExit:
            print "Exit"
        except a:
            print "Recovering from error"
            import shell
        try:
            a = "sh: " + cmd + ": " + "command not found"
            tab = readline.parse_and_bind('tab: complete')
            readline.insert_text(cmdlist)
            if cmd == '':
                print "Error: blank command"
                import shell
        except NameError:
            while True:
                print("Error reloading")
                import shell
        for i, elem in enumerate(blcnf):
            if cmd in elem:
                print("Not Allowed cmd: " + elem + " @ " + timer + " By: " + getpass.getuser())
                logger.write("blacklist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                level = 3
                quit()
                logger.close()
        for i, elem in enumerate(whcnf):
            if cmd == elem:
                print("Allowed but logged: " + elem + "\n" + timer + " By: " + getpass.getuser() + '\n')
                logger.write("Whitelist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                risk = level + 1
                srisk = (rip - risk)
                print("Warning: "
                "{0} commands left before whitelist policy invalidates session".format(str(srisk))
                )
                print("Warning: "
                    "Risk has evalated to {0} ".format(str(risk))
                )
                level = risk
                srisk = rip
        if cmd == 'chdir':
            try:
                g = raw_input("Dir: ")
                os.chdir(g)
            except a:
                print "Parse issue"
                import shell
            except OSError:
                print "Dir Error"
                import shell
        if cmd in 'cd':
            try:
                g = raw_input("Dir: ")
                os.chdir(g)
            except a:
                print "Parse issue"
                import shell
            except OSError:
                print "Dir Error"
                import shell
        if cmd == 'exit':
            print("Exiting\n")
            quit()
            logger.write("Whitelist cmd: " + cmd + " @ " + timer + " By: " + getpass.getuser() + '\n')
            logger.close()
        if cmd == 'risk':
            while True:
                print "Risk: ", level, "\n"
                break
                import shell
        if cmd == 'risk.reset':
            while True:
                print "Reseting Risk: "
                print "Current Risk: ", level, "\n"
                level = 0
                print "New Risk: ", level, "\n"
                logger.write("Risk reset: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                break
                import shell
        if cmd == 'threshold':
            while True:
                print "Threshold: ", rip, "\n"
                break
                import shell
        if cmd == 'threshold.set':
            while True:
                th = raw_input("Threshold: ")
                print "Current threshold: ", rip, "\n"
                rip = th
                print "New threshold: ", rip, "\n"
                print("Reloading shell")
                logger.write("Threshold set: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                break
                import shell
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
            logger.write(
                "SSH Shell Started" + " @ " + time.asctime() + " By: " + getpass.getuser() + " as " + usr + "@" + host + "\n")
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
                    logger.write(
                        "Protocol Error: " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + "\n")
                    import shell
                except paramiko.transport:
                    print "General Error"
                    logger.write(
                        "Protocol Error: " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + "\n")
                    import shell
                except socket.error:
                    print "Socket Error"
                    logger.write(
                        "Socket Error: " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + "\n")
                    import shell
                cmd = raw_input("Secure-SSH-Shell=> ")
                if level == rip:
                    print("Insider threat detected")
                    logger.write(
                        "Insider Threat Detected: " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + '\n')
                    import shell

                    break
                for i, elem in enumerate(blcnf):
                    if cmd in elem:
                        print(
                            "Not Allowed cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + " as " + usr + "@" + host + "\n")
                        logger.write(
                            "SSH blacklist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + " as " + usr + "@" + host + '\n')
                        level = 3
                        logger.close()
                        import shell
                for i, elem in enumerate(whcnf):
                    if cmd in elem:
                        print(
                            "Allowed but logged: " + elem + "\n" + timer + " By " + getpass.getuser() + " as " + usr + "@" + host + '\n')
                        logger.write(
                            "SSH whitelist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + " as " + usr + "@" + host + '\n')
                    risk = level + 1
                    srisk = (rip - risk)
                    print("Warning: "
                    "{0} commands left before whitelist policy invalidates session".format(str(srisk))
                    )
                    print("Warning: "
                    "Risk has evalated to {0} ".format(str(risk))
                    )
                level = risk
                srisk = rip
                if cmd == 'exit':
                    print("Exiting\n")
                    logger.write("Exiting: " + cmd + " @ " + timer + " By: " + getpass.getuser() + '\n')
                    break
                try:
                    stdin, stdout, stderr = client.exec_command(cmd)
                    a = stdout.readlines()
                    print ''.join(a)
                except AttributeError:
                    print "Attribute Error"
                    import shell
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
            import shell
        if cmd == '':
            print "Blank command detected"
        if cmd in a:
            print "\n"
        if cmd in "sh:":
            print "Recovering from error"
            import shell
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
            except SystemError:
                print "Unknown Error"
                import shell
            except (KeyboardInterrupt, SystemExit):
                print "exiting \n"
                quit()
            except systemCMD:
                print "Unknown error"
                import shell
            if errorseq:
                print "Error Logged"
                logger.write("Error: " + a + " @ " + timer + " By: " + getpass.getuser() + '\n')
    if __name__ == __init__():
        import shell