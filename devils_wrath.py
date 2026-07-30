#!/usr/bin/env python3
import argparse
from colorama import init, Fore
from impacket.dcerpc.v5 import samr
from impacket.smbconnection import SMBConnection

# Initialize colorama for clean terminal output
init(autoreset=True)

BANNER = f"""
{Fore.RED}██████╗ ███████╗██╗   ██╗██╗██╗     ███████╗    ██╗    ██╗██████╗  █████╗ ████████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║██║     ██╔════╝    ██║    ██║██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
██║  ██║█████╗  ██║   ██║██║██║     ███████╗    ██║ █╗ ██║██████╔╝███████║   ██║   ███████║
██║  ██║██╔══╝  ╚██╗ ██╔╝██║██║     ╚════██║    ██║███╗██║██╔══██╗██╔══██║   ██║   ██╔══██║
██████╔╝███████╗ ╚████╔╝ ██║███████╗███████║    ╚███╔███╔╝██║  ██║██║  ██║   ██║   ██║  ██║
╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚══════╝╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
                {Fore.YELLOW}Active Directory Misconfiguration Scanner | GitHub Edition
"""

def parse_args():
    parser = argparse.ArgumentParser(description="Devil's Wrath - AD Auditing Tool")
    parser.add_argument('-t', '--target', required=True, help="Target IP or Domain Controller FQDN")
    parser.add_argument('-d', '--domain', required=True, help="AD Domain Name (e.g., local.corp)")
    parser.add_argument('-u', '--username', required=True, help="Domain username")
    parser.add_argument('-p', '--password', required=True, help="Domain password")
    return parser.parse_args()

# =====================================================================
# STEP 1: NULL SESSION & ANONYMOUS BIND CHECK
# =====================================================================
def step_one_null_session(target):
    print(f"\n{Fore.CYAN}[+] STEP 1: Checking for SMB Null Sessions...")
    try:
        smb = SMBConnection(target, target, sess_port=445)
        smb.login('', '')
        print(f"{Fore.RED}[!] CRITICAL: Null Session Allowed! Unauthenticated users can list network details.")
        smb.logoff()
    except Exception:
        print(f"{Fore.GREEN}[✓] Secure: SMB Null Sessions are disabled.")

# =====================================================================
# STEP 2: USER ACCOUNT POLICY & BLANK PASSWORD AUDIT
# =====================================================================
def step_two_policy_audit(target, domain, username, password):
    print(f"\n{Fore.CYAN}[+] STEP 2: Auditing Domain Password Policies & Users...")
    try:
        smb = SMBConnection(target, target, sess_port=445)
        smb.login(username, password, domain)
        
        rpc = smb.get_dce_rpc('samr')
        rpc.connect()
        rpc.bind(samr.MSRPC_UUID_SAMR)
        
        server_handle = samr.hSamrConnect(rpc)['ServerHandle']
        domain_sid = samr.hSamrLookupDomainInSamServer(rpc, server_handle, domain)['DomainId']
        domain_handle = samr.hSamrOpenDomain(rpc, server_handle, domainId=domain_sid)['DomainHandle']
        
        info = samr.hSamrQueryInformationDomain(rpc, domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        min_length = info['DomainPassword']['MinPasswordLength']
        
        print(f"{Fore.YELLOW}[i] Minimum Password Length Policy: {min_length} characters")
        if min_length < 8:
            print(f"{Fore.RED}[!] WARNING: Short password policy detected ({min_length} chars). Vulnerable to brute-forcing.")
        else:
            print(f"{Fore.GREEN}[✓] Password length policy is acceptable.")
            
        smb.logoff()
    except Exception as e:
        print(f"{Fore.RED}[-] Step 2 Failed: Connection refused or insufficient privileges.")

# =====================================================================
# STEP 3: HIGH-RISK SHARE & MISCONFIGURATION ENUMERATION
# =====================================================================
def step_three_share_enum(target, domain, username, password):
    print(f"\n{Fore.CYAN}[+] STEP 3: Scanning SMB Shares for Dangerous Paths...")
    try:
        smb = SMBConnection(target, target, sess_port=445)
        smb.login(username, password, domain)
        
        shares = smb.listShares()
        dangerous_shares = ['C$', 'ADMIN$', 'SYSVOL', 'NETLOGON']
        
        print(f"{Fore.YELLOW}[i] Accessible shares found:")
        for share in shares:
            share_name = share['shi1_netname'].decode('utf-16-le').strip('\x00')
            print(f"    -> {share_name}")
            
            if share_name in dangerous_shares:
                print(f"{Fore.MAGENTA}    [!] Note: Standard management share '{share_name}' is visible. Ensure ACLs are strict.")
                
        smb.logoff()
    except Exception as e:
        print(f"{Fore.RED}[-] Step 3 Failed: Could not enumerate shares.")

if __name__ == '__main__':
    print(BANNER)
    args = parse_args()
    
    step_one_null_session(args.target)
    step_two_policy_audit(args.target, args.domain, args.username, args.password)
    step_three_share_enum(args.target, args.domain, args.username, args.password)
    
    print(f"\n{Fore.GREEN}[✓] Devil's Wrath scan complete.")
