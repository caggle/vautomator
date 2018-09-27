import subprocess
import dns.resolver


def isToolAvailable(toolname):
    try:
        status, output = subprocess.getstatusoutput('which '.join(toolname))
        if status == 0:
            return True
        else:
            try:
                status, output = subprocess.getstatusoutput(toolname)
                if status == 0:
                    return True
            except BaseException:
                return False
            return False

    except OSError:
        return False


def resolveDNS(target, record_type):
    custom_resolver = dns.resolver.Resolver()
    # 8.8.8.8 is Google's public DNS server
    custom_resolver.nameservers = ['8.8.8.8']
    answer = custom_resolver.query(target, record_type)
    return answer
