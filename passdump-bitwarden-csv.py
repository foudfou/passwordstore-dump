#!/usr/bin/env python3

import re
import os
import subprocess

EXCLUDE_ENTRIES_RE = r'(^\.git)' \
    + r'|\.gpg-id' \
    + r'|\.zip' \
    + r'|(-backup$)'

DOMAIN_RE = re.compile(r"^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}")
IP4_RE = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
LOGIN_USERNAME_RE = r'^(?:user|login|username).* ?: ?(.*)$'
FIELD_RE = r'^(\S+): (\S+.*)$'

def traverse(directory):
    pass_files = []

    for root, dirs, files in os.walk(directory):
        for name in files:
            pass_files.append(os.path.join(root, name))

    return pass_files

def _is_domain(component):
    return re.search(DOMAIN_RE, component) \
        or re.search(IP4_RE, component) \
        or component.startswith("localhost")


def slurp_pass(entry):
    content = subprocess.run(['pass', entry], check=True, capture_output=True)
    return content.stdout.rstrip().decode("utf-8")

# Heuristic: if there are components after a domain-like one, then the
# last one is the username. TODO how do we build the name?
def extract_username_from_path(components):
    username = ""
    uri = ""

    for idx, component in enumerate(components):
        if _is_domain(component):
            if idx == len(components)-1:
                if '@' in components[-1]:
                    username = components[-1]
                else:
                    # bw_username inside file
                    # print("__YYY", components[-1])
                    pass
            elif idx == len(components)-2:
                username = components[-1]
            else:
                # print("__XXX", components)
                username = components[-1]

            # Heuristic: URL usually the first component after the folder
            if idx == 1 and components[0] == "http":
                uri = "https://" + components[1]

            break

    return (username, uri)


def process_entry(entry):
    components = entry.split('/')
    # print(components)

    # https://bitwarden.com/help/condition-bitwarden-import/#for-your-individual-vault
    bw_row = {
        'folder': "pass/" + components[0], # prefix to review after import
        'favorite': None,
        'type': "login",
        'name': '/'.join(components[1:]),
        'notes': [],
        'fields': [],
        'reprompt': None,
        'login_uri': "",
        'login_username': "",
        'login_password': "",
    }

    (bw_row['login_username'],
     bw_row['login_uri']) = extract_username_from_path(components)

    if bw_row['login_username']:
        bw_row['name'] = '/'.join(components[1:-1])

    lines = slurp_pass(entry).split('\n')

    bw_row['login_password'] = lines[0]

    for line in lines[1:]:
        match = re.search(LOGIN_USERNAME_RE, line, re.I | re.M)
        if match:
            if not bw_row['login_username']:
                bw_row['login_username'] = match.group(1)
            continue

        match = re.search(FIELD_RE, line, re.I | re.M)
        if match:
            bw_row['fields'].append(line)
            continue

        bw_row['notes'].append(line)

    if not bw_row['login_username']:
        print("__NO_USERNAME:", entry)

    # print(bw_row['name'])
    print('.', end='', flush=True)

    bw_row['notes']  = '\n'.join(bw_row['notes'])
    bw_row['fields'] = '\n'.join(bw_row['fields'])

    return bw_row


def write_csv(data, output_file):
    import csv

    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(data[0].keys()))

        writer.writeheader()

        for row in data:
            writer.writerow(row)


def main():
    home = os.environ['HOME']
    store_path = os.path.join(home, ".password-store")
    encrypted_files = traverse(store_path)

    entries = []
    for path in encrypted_files:
        match = re.search(r'^' + store_path + r'\/(.*)\.gpg$', path)
        if match:
            entry = match.group(1)

            exclude = re.search(re.compile(EXCLUDE_ENTRIES_RE), entry)
            if exclude:
                print("_EXCLUDED: ", exclude.group(0))
                continue

            entries.append(process_entry(entry))

    write_csv(entries, "bw.csv")


if __name__ == '__main__':
    main()
