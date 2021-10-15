#!/usr/bin/env python3

import os,argparse

nullbot_dir = "$HOME/tools/nullbot"
version = "v0.3"

def Banner():
    head = """----------------------------------------\n\033[0;34mNullBot Scanner\033[0m\n\033[0;33m{}\033[0m - \033[0;32m@NullCell8822\033[0m\n----------------------------------------\n""".format(version)
    print(head)

def recon(domain):
    os.system('{}/modules/recon/recon.sh {}'.format(nullbot_dir, domain))

def ctf(ip):
    os.system('{}/modules/ctf/ctf.sh {}'.format(nullbot_dir, ip))

def main():
    # Define argument parser
    parser = argparse.ArgumentParser(description='\033[0;34mNullBot\033[0m - \033[0;33m{}\033[0m'.format(version))
    # Arguments that can be supplied
    domain_group = parser.add_mutually_exclusive_group()
    domain_group.add_argument('-d', '--domain', help='Target domain', dest='domain', type=str, nargs='?')
    domain_group.add_argument('-t', '--target', help='Target IP address or hostname', dest='ip', type=str, nargs='?')
    parser.add_argument('-m', '--module', help='Module to run', dest='module', type=str, nargs='?', choices=['all','recon','ctf','redirect'], required=True)

    # Parse arguments
    args = parser.parse_args()

    # Show banner
    Banner()

    # Check Arguments
    if args.module == 'recon':
        if args.domain == None:
            print("Error, please enter a domain using -d/--domain flag")
        else:
            print("Running Bug Bounty recon on {}".format(args.domain))
            recon(args.domain)
    elif args.module == 'ctf':
        if  args.ip == None:
            print("Error, please enter target IP address using -t/--target flag")
        else:
            print("Running CTF Automated scan on {}".format(args.ip))
            ctf(args.ip)
    else:
        print("\033[0;31m[x]\033[0m Invalid Arguments, check -h/--help")

if __name__ == "__main__":
    main()
