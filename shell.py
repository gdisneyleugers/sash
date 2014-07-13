#!/bin/env python
__author__ = 'gregorydisney'
__name__ = '__main__'
import os
import time
import readline
import getpass
import socket
from os import system as sys
from subprocess import call
import paramiko
import yaml
import shell
import sys as backend
from yaml import load as config


logger = file('shell.log', 'a')
logger.write("Shell Started" + " @ " + time.asctime() + " By: " + getpass.getuser() + "\n")


class SystemCmd:
    def __init__(self):
        __init__ = '__name__'
    def cmd(self):
        self = raw_input('Secure-Shell=> ')
        sys(self)
    blcnf = config(file('blacklist.yaml', 'r'))
    whcnf = config(file('whitelist.yaml', 'r'))
    cmdcnf = config(file('cmd.yaml', 'r'))
    cmdlist = ''.join(cmdcnf)
    level = 0
    risk = level
    rip = 3
    srisk = rip
    builtin = "echo >> /dev/null"
    while True:
        try:
            import readline
        except ImportError:
            print "Module readline not available."
        else:
            import rlcompleter
            if backend.platform == 'darwin':
                readline.parse_and_bind ("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
            readline.insert_text(cmdlist)
            c = rlcompleter.Completer()
            d = rlcompleter.Completer.complete(c, text=cmdlist,state=0)
            readline.get_completer()
            readline.insert_text(cmdlist)

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
            a = "sh: " + cmd + ": " + "command not found"
        except KeyboardInterrupt:
            print "\n"
            print "Exiting \n"
            quit()
        except SystemError:
            print "Exit"
        except SystemExit:
            print "Exit"

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
                logger.write("Whitelist cmd: " + elem + " @ " + timer + " By: " + getpass.getuser() + '\n')
                risk = level + 1
                srisk = (int(rip) - int(risk))
                print("Warning: "
                "{0} commands left before whitelist policy invalidates session".format(str(srisk))
                )
                print("Warning: "
                    "Risk has evalated to {0} ".format(str(risk))
                )
                if srisk <= 0:
                    print "Fatal: Policy threshold met"
                    logger.write("Threshold level: " + str(srisk) + " @ " + timer + " By: " + getpass.getuser() + '\n')
                    quit()
                level = risk
                srisk = rip
        if cmd == 'chdir':
            try:
                g = raw_input("Dir: ")
                def chdir(self, cmd):
                    call("chdir", shell=True)
                os.chdir(g)
                cmd = builtin
                import shell
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
                print "Risk: ", level, "\n"
                cmd = builtin
        if cmd == 'risk.reset':
                print "Reseting Risk: "
                print "Current Risk: ", level, "\n"
                level = 0
                print "New Risk: ", level, "\n"
                logger.write("Risk reset: " + str(level) + " @ " + timer + " By: " + getpass.getuser() + '\n')
                cmd = builtin
        if cmd == 'threshold':
                print "Threshold: ", rip, "\n"
                cmd = builtin
        if cmd == 'threshold.set':
                th = raw_input("Threshold: ")
                print "Current threshold: ", rip, "\n"
                rip = th
                print "New threshold: ", rip, "\n"
                logger.write("Threshold set: " + str(th) + " @ " + timer + " By: " + getpass.getuser() + '\n')
                cmd = builtin
                if risk == srisk:
                    print "Fatal: Policy threshold met"
                    quit()
        if cmd == 'ssh.shell':
            try:
                client = paramiko.SSHClient()
                host = raw_input("Host: ")
                SSH_PORT = input("Port: ")
                usr = raw_input("User: ")
            except (KeyboardInterrupt, SystemExit):
                print "exiting \n"
                quit()
            except SyntaxError:
                print "Error"
                import shell
            if not usr:
                user = getpass.getuser()
            if usr == '':
                user = getpass.getuser()
            pwd = getpass.getpass("Password: ")
            if not pwd:
                pwd = getpass.getpass
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
                except KeyboardInterrupt:
                    print "Exiting\n"
                    import shell
                except EOFError:
                    print "Exiting\n"
                    quit()
                cmd = raw_input("Secure-SSH-Shell=> ")
                if level == rip:
                    print("Invalidating session")
                    logger.write(
                        "Fatal: Policy threshold met " + " @ " + timer + " By: " + getpass.getuser() + usr + "@" + host + '\n')
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
            print("{0}".format(cmd))
            cmd = builtin
        if cmd == 'time.now':
            print(timer)
            cmd = builtin
        if cmd == 'user.name':
            print getpass.getuser()
            cmd = builtin
        if cmd == 'overlay.import':
            imp = raw_input("Import sash module: ")
            ext = ".sash"
            if not ext in imp:
                print "Not SASH module"
                cmd = builtin
            if ext in imp:
                sys("python {0}".format(imp))
                cmd = builtin
                import shell
        if cmd == 'shell.script':
            imp = raw_input("Import sash shell script: ")
            ext = ".shell"
            if not ext in imp:
                print "Not SASH script"
                cmd = builtin
                import shell
            if ext in imp:
                sys("chmod u+x {0}".format(imp))
                sys("./{0}".format(imp))
                cmd = builtin
                import shell
        if cmd == 'alter.list':
            readline.add_history(cmd)
            cmd = builtin
            try:
                a = raw_input("whitelist or blacklist: ")
            except KeyboardInterrupt:
                print "Reloading shell\n"
                import shell
            if a == 'blacklist':
                blcmd = raw_input("Cmd to Blacklist: ")
                print("Blacklisting for this session => " + blcmd)
                d = [blcmd, blcnf]
                blcnf = d
                cmd = builtin
            if a == 'whitelist':
                whcmd = raw_input("Cmd to whitelist: ")
                print("whitelisting for this session => " + whcmd)
                b = [whcmd, whcnf]
                whcnf = b
                cmd = builtin
                if a == 'exit':
                    import shell
        if cmd == 'policy.list':
            readline.add_history(cmd)
            print "Whitelist:", whcnf
            print "Blacklist:", blcnf
            cmd = builtin
        if cmd == '':
            print "Blank command detected"
        if cmd in a:
            print "\n"
        if cmd in "sh:":
            print "Recovering from error"
        else :
            try:
                error = sys(cmd)
                errorseq = error > 0
                import shell
            except a:
                print "Shell bleed through\n"
                import shell
                print "\n"
            except OSError:
                print "\n"
                import shell
                print "\n"
            except IOError:
                print "IO Error"
                import shell
            except SystemError:
                print "Unknown Error"
                import shell
            except (KeyboardInterrupt, SystemExit):
                print "exiting \n"
                quit()
            if errorseq:
                print "Error Logged"
                logger.write("Error: " + a + " @ " + timer + " By: " + getpass.getuser() + '\n')
if __name__ == '__main__':
    try:
        SystemCmd
    except EOFError:
        print "\n"
        quit()
    except NameError:
        print "\n"