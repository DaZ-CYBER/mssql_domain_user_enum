#!/usr/bin/python3

import sys
import argparse
import pymssql

output_file = []

def arguments():
    parser = argparse.ArgumentParser(description="Tool for Domain User Enumeration via MSSQL by DaZ", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-s', '--server', help="target server (IP or Domain)", required=True, default=argparse.SUPPRESS)
    parser.add_argument('-pt', '--port', type=int, help="target MSSQL port", default=1433)
    parser.add_argument('-u', '--username', help="username to authenticate as", required=True, default=argparse.SUPPRESS)
    parser.add_argument('-p', '--password', help="password to authenticate as", required=True, default=argparse.SUPPRESS)
    parser.add_argument('-mi', '--minimum-rid', type=int, help="minimum RID value for enum", default=500)
    parser.add_argument('-ma', '--maximum-rid', type=int, help="maximum RID value for enum", default=512)
    parser.add_argument('-o', '--output', help="return output to user-list file", default=argparse.SUPPRESS)

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    config = vars(args)

    return(config)

def test_mssql_connection(server, port, database, username, password):
    try:
        conn = pymssql.connect(
            server=server,
            port=port,
            user=username,
            password=password,
            database=database,
            login_timeout=5
        )
        print(f"[+] Connection to {server} established successfully.")
        return conn

    except pymssql.OperationalError as e:
        # e.args[0] contains the numeric error code (e.g., 20009)
        error_code = e.args[0] if e.args else "UNKNOWN"
        print(f"[x] MSSQL connection failed (Error {error_code})")
        sys.exit(1)

    except pymssql.DatabaseError as e:
        error_code = e.args[0] if e.args else "UNKNOWN"
        print(f"[x] MSSQL database error (Error {error_code})")
        sys.exit(1)

    except Exception as e:
        print(f"[x] Unexpected error: {e}")
        sys.exit(1)

    print(f"[+] Connection to {server} established successfully.")
    return(conn)

def extract_domain_sid(conn):
    print(f"[*] Extracting domain NETBIOS name...")
    cursor = conn.cursor()
    query = "SELECT DEFAULT_DOMAIN();"
    cursor.execute(query)

    query_result = cursor.fetchone()
    if query_result:
        domain = query_result[0]
    print(f"[+] Retrieved domain: {domain}")

    print(f"[*] Extracting SID for group Domain Users...")
    query = f"SELECT SUSER_SID('{domain}\\Domain Users')"
    cursor.execute(query)

    query_result = cursor.fetchone()
    if query_result:
        sid = query_result[0]
        hex = f"0x{sid[:-4].hex()}"

    print(f"[+] Retrieved SID: {hex}")
    return hex

def try_rid(conn, sid_rid_hex):
    cursor = conn.cursor()
    query  = f"SELECT SUSER_SNAME({sid_rid_hex})"
    cursor.execute(query)

    query_result = cursor.fetchone()
    if query_result and query_result[0] is not None:
        user = query_result[0]
        print(f"[+] Found User: {user}")
        output_file.append(user.split("\\")[1])

def hex_conversion(rid_value):
    little_endian = rid_value.to_bytes(2, byteorder="big")[::-1]
    rid = little_endian.hex()
    formatted_rid = f"{rid}0000"
    return formatted_rid

def start(config):
    server      = config['server']
    port        = config['port']
    username    = config['username']
    password    = config['password']
    minimum_rid = config['minimum_rid']
    maximum_rid = config['maximum_rid']
    database = 'msdb'

    print(f"[*] Testing connection to {server}...")
    conn = test_mssql_connection(server, port, database, username, password)
    domain_sid_hex = extract_domain_sid(conn)
    for rid in range(minimum_rid,maximum_rid):
        hex_rid = hex_conversion(rid)
        try_rid(conn, f"{domain_sid_hex}{hex_rid}")
    
    if config.get('output'):
        with open(config['output'], 'w') as f:
            for user in output_file:
                f.write(f"{user}\n")
        
        print(f"[*] Usernames written to \"{config['output']}\"")
        f.close()

if __name__ == "__main__":
    config = arguments()
    start(config)