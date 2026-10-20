import subprocess
import sys
import random
import os

# ─────────────────────────────────────────────
#  AUTO-INSTALL PARAMIKO IF MISSING
# ─────────────────────────────────────────────
def ensure_package(package):
    try:
        __import__(package)
    except ImportError:
        print(f"[SETUP] '{package}' not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"[SETUP] '{package}' installed successfully.")

ensure_package("paramiko")
import paramiko

# ─────────────────────────────────────────────
#  CONFIG — edit these before running
# ─────────────────────────────────────────────
NAS_HOST        = "192.168.x.x"                   # NAS IP or hostname (eg, nas.local, homestorage.local. Set by the admin)
NAS_PORT        = 22                                # SFTP runs over SSH (default port 22)
NAS_USERNAME    = "###"
NAS_PASSWORD    = "###"  # Password assigned to your user by the admin, Or use key-based auth
NAS_FILE_PATH   = "###"  # your passwords.txt file get stored in the NAS, specify which directory and subdirectory of the subdirectory and so on.

LOCAL_FILE      = "passwords.txt"           # Local copy path

# Optional: use SSH key instead of password
# Set NAS_PASSWORD = None and provide the path to your private key
SSH_KEY_PATH    = None                              # e.g. "/home/user/.ssh/id_rsa"
# ─────────────────────────────────────────────


def connect_sftp():
    """Establish SSH connection and return (ssh_client, sftp_client)."""
    try:
        ssh = paramiko.SSHClient()

        # Automatically accept unknown host keys (see note below)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if SSH_KEY_PATH:
            private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
            ssh.connect(NAS_HOST, port=NAS_PORT, username=NAS_USERNAME, pkey=private_key)
        else:
            ssh.connect(NAS_HOST, port=NAS_PORT, username=NAS_USERNAME, password=NAS_PASSWORD)

        sftp = ssh.open_sftp()
        print("[SFTP] Connected successfully.")
        return ssh, sftp

    except paramiko.AuthenticationException:
        print("[SFTP] Authentication failed. Check username/password or SSH key.")
    except paramiko.SSHException as e:
        print(f"[SFTP] SSH error: {e}")
    except Exception as e:
        print(f"[SFTP] Could not connect: {e}")

    return None, None


def ensure_remote_dir(sftp, remote_path):
    """Create remote directory tree if it doesn't exist."""
    dirs = os.path.dirname(remote_path).split("/")
    current = ""
    for d in dirs:
        if not d:
            continue
        current += "/" + d
        try:
            sftp.stat(current)
        except FileNotFoundError:
            sftp.mkdir(current)
            print(f"[SFTP] Created remote directory: {current}")


def read_nas_file(sftp):
    """Read and return lines from the NAS file."""
    import io
    try:
        with sftp.open(NAS_FILE_PATH, "r") as f:
            return f.read().decode("utf-8").splitlines()
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[SFTP] Error reading NAS file: {e}")
        return []


def write_nas_file(sftp, lines):
    """Write the full updated line list back to the NAS file."""
    import io
    try:
        ensure_remote_dir(sftp, NAS_FILE_PATH)
        content = "\n".join(lines) + "\n" if lines else ""
        with sftp.open(NAS_FILE_PATH, "w") as f:
            f.write(content)
        print("[SFTP] NAS file updated.")
    except Exception as e:
        print(f"[SFTP] Error writing NAS file: {e}")


def load_local_strings():
    """Load previously generated strings from the local file."""
    used = set()
    if os.path.exists(LOCAL_FILE):
        with open(LOCAL_FILE, "r") as f:
            for line in f:
                s = line.strip()
                if s:
                    used.add(s)
    return used


def sync_from_nas(sftp):
    """
    Startup sync: NAS → Local.
    Merges NAS entries into local file and returns the full combined set.
    """
    nas_lines  = read_nas_file(sftp)
    nas_set    = set(line.strip() for line in nas_lines if line.strip())
    local_set  = load_local_strings()
    combined   = nas_set | local_set

    nas_only = nas_set - local_set
    if nas_only:
        with open(LOCAL_FILE, "a") as f:
            for s in sorted(nas_only):
                f.write(s + "\n")
        print(f"[SYNC] Pulled {len(nas_only)} new entry/entries from NAS into local file.")

    print(f"[SYNC] {len(combined)} total unique string(s) loaded (NAS + local combined).")
    return combined


def sync_to_nas(sftp, new_strings):
    """
    End-of-batch sync: Local → NAS.
    Appends only newly generated strings that aren't already on the NAS.
    """
    nas_lines = read_nas_file(sftp)
    nas_set   = set(line.strip() for line in nas_lines if line.strip())
    to_add    = [s for s in new_strings if s not in nas_set]

    if to_add:
        updated = [l.strip() for l in nas_lines if l.strip()] + to_add
        write_nas_file(sftp, updated)
        print(f"[SYNC] Pushed {len(to_add)} new string(s) to NAS.")
    else:
        print("[SYNC] NAS already up to date. Nothing pushed.")


def append_local(s):
    """Append a single new string to the local file immediately."""
    with open(LOCAL_FILE, "a") as f:
        f.write(s + "\n")


def generate_string(used_strings):
    digits    = list("0123456789")
    lowercase = list("abcdefghijklmnopqrstuvwxyz")
    uppercase = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    symbols   = list("!@#$%^{}")

    max_attempts = 10000

    for _ in range(max_attempts):
        symbol_count = {}

        chosen_digits = random.sample(digits,    random.randint(1, 3))
        chosen_lower  = random.sample(lowercase, random.randint(2, 6))
        chosen_upper  = random.sample(uppercase, random.randint(2, 6))

        non_symbols = chosen_digits + chosen_lower + chosen_upper
        if len(non_symbols) < 12:
            continue

        non_symbol_seq = random.sample(non_symbols, 12)

        chosen_symbols = []
        for _ in range(3):
            available = [s for s in symbols if symbol_count.get(s, 0) < 2]
            if not available:
                break
            s = random.choice(available)
            chosen_symbols.append(s)
            symbol_count[s] = symbol_count.get(s, 0) + 1

        if len(chosen_symbols) < 3:
            continue

        result  = []
        ns_idx  = 0
        sym_idx = 0
        for i in range(15):
            if i in (3, 7, 11):
                result.append(chosen_symbols[sym_idx])
                sym_idx += 1
            else:
                result.append(non_symbol_seq[ns_idx])
                ns_idx += 1

        final_string = ''.join(result)
        if final_string not in used_strings:
            return final_string

    return None


def get_valid_count():
    while True:
        try:
            count = int(input("How many strings would you like to generate? "))
            if count <= 0:
                print("Please enter a positive integer.")
            else:
                return count
        except ValueError:
            print("Invalid input. Please enter a whole number.")


def main():
    print("=== Random String Generator (SFTP) ===")
    print(f"Local file  : {os.path.abspath(LOCAL_FILE)}")
    print(f"NAS target  : {NAS_HOST}:{NAS_FILE_PATH}\n")

    # Step 1: Connect via SFTP
    ssh, sftp = connect_sftp()

    # Step 2: Sync and load known strings
    if sftp:
        used_strings = sync_from_nas(sftp)
    else:
        print("[WARN] Running in local-only mode. NAS sync unavailable.")
        used_strings = load_local_strings()

    session_active  = True
    session_strings = []

    while session_active:
        count = get_valid_count()
        print(f"\nGenerating {count} unique string(s)...\n")

        batch_strings = []
        failed        = 0

        for i in range(count):
            result = generate_string(used_strings)
            if result:
                used_strings.add(result)
                batch_strings.append(result)
                session_strings.append(result)
                append_local(result)                    # Write to local immediately
                print(f"  [{i+1:>4}] {result}")
            else:
                print(f"  [{i+1:>4}] Could not generate a unique string after max attempts.")
                failed += 1

        # Push batch to NAS
        if sftp and batch_strings:
            sync_to_nas(sftp, batch_strings)

        print(f"\n  Local      : {os.path.abspath(LOCAL_FILE)}")
        print(f"  Generated  : {len(batch_strings)} | Session: {len(session_strings)} | All-time: {len(used_strings)}")
        if failed:
            print(f"  Failed     : {failed}")

        again = input("\nGenerate more strings? (yes/no): ").strip().lower()
        if again not in ("yes", "y"):
            session_active = False

    # Clean up connections
    if sftp:
        sftp.close()
    if ssh:
        ssh.close()
        print("\n[SFTP] Connection closed.")

    print(f"Session ended. Total unique strings ever generated: {len(used_strings)}")


if __name__ == "__main__":
    main()
