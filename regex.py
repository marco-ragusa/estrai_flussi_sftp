import re


def line_parser(line):
    search = re.search('(?P<date>^\S+\s+\S+\s+\S+).+sshd\[(?P<pid>\d+)\]: (?P<message>.*)', line)
    try:
        parsed = search.groupdict()
        parsed['date'] = re.sub('\s+', ',', parsed['date'])
        return parsed
    except AttributeError:
        pass


def user(text):
    search = re.search('Accepted password for (\S+) from \S+', text)
    try:
        return search.group(1)
    except AttributeError:
        return ''


def ip(text):
    search = re.search('Accepted password for \S+ from (\S+)', text)
    try:
        return search.group(1)
    except AttributeError:
        return ''


def user2(text):
    search = re.search('session opened for local user (\S+) from \[\S+\]', text)
    try:
        return search.group(1)
    except AttributeError:
        return ''


def ip2(text):
    search = re.search('session opened for local user \S+ from \[(\S+)\]', text)
    try:
        return search.group(1)
    except AttributeError:
        return ''


def download(text):
    file = ''
    file2 = ''
    files = re.findall(r'(".*?")', text)

    try:
        file = files[0]
    except IndexError:
        pass

    action = 'download' if 'forced' not in text else 'download broken'

    return {'action': action, 'file': file, 'file2': file2}


def upload(text):
    file = ''
    file2 = ''
    files = re.findall(r'(".*?")', text)

    try:
        file = files[0]
    except IndexError:
        pass
    
    action = 'upload' if 'forced' not in text else 'upload broken'

    return {'action': action, 'file': file, 'file2': file2}


def remove(text):
    file = ''
    file2 = ''
    files = re.findall(r'(".*?")', text)

    try:
        file = files[0]
    except IndexError:
        pass
    
    return {'action': 'remove', 'file': file, 'file2': file2}


def rmdir(text):
    file = ''
    file2 = ''
    files = re.findall(r'(".*?")', text)

    try:
        file = files[0]
    except IndexError:
        pass

    return {'action': 'rmdir', 'file': file, 'file2': file2}


def mkdir(text):
    file = ''
    file2 = ''
    files = re.findall(r'(".*?")', text)

    try:
        file = files[0]
    except IndexError:
        pass

    return {'action': 'mkdir', 'file': file, 'file2': file2}


def rename(text):
    file = ''
    file2 = ''
    files = re.findall(r'(".*?")', text)

    try:
        file = files[0]
    except IndexError:
        pass

    try:
        file2 = files[1]
    except IndexError:
        pass

    return {'action': 'rename', 'file': file, 'file2': file2}
