#!/usr/bin/env python3

import os,argparse

def Banner():
    head = """----------------------------------------\nNullBot Recon\nv0.2 - @NullCell8822\n----------------------------------------"""
    print(head)

def Recon(domain):
    print('Executing recon script on ' + domain + '\n')
    os.system('./modules/recon/recon.sh ' + domain)

# Start of main
# Define argument parser
parser = argparse.ArgumentParser(description='NullBot')
# Arguments that can be supplied
parser.add_argument('-d', '--domain', help='Target domain', dest='domain', nargs=1, required=True)
parser.add_argument('-m', '--module', help='Module to run. Default: recon', dest='module', type=str, nargs='?', choices=['all','recon','redirect'], default='recon')

# Parse arguments
args = parser.parse_args()

# Show banner
Banner()
# Check Arguments
if args.module == 'recon':
    Recon(args.domain[0])

