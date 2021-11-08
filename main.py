########################################
#
# Autore: Marco Ragusa
# Licenza: GPL3
# Linguaggio: Python2, Python3
# Risorse min: RAM 2GB, 2 CPU
#
########################################

import os
# Locale
import regex


logs_path = '.\\var\\log'
dict_collection = {}


def get_full_logs_path(logs_path):
    result = []
    for file in os.listdir(logs_path):
        # Prende solo i "secure" file
        if "secure" in file:
            result.append(os.path.join(logs_path, file))
    return result


def get_lines(file_path):
    with open(file_path, 'r') as f:
        return f.readlines()


def pid_collector(dict_log_line):
    pid = dict_log_line['pid']
    message = dict_log_line['message']

    # Se il pid non esiste aggiunge una lista con il pid
    if pid not in dict_collection:
        dict_collection[pid] = []

    # Aggiungo la linea usando come metodo di raggruppamento
    # la chiave pid del dizionario
    dict_collection[pid].append(dict_log_line)

    # Quando la sessione e' chiusa scrive la lista delle operazioni
    if 'session closed for user' in message:
        pid_processor({pid: dict_collection[pid]})


def action_match(message):
    if 'written 0' in message:
        return regex.download(message)

    if 'read 0' in message:
        return regex.upload(message)

    if 'remove' in message:
        return regex.remove(message)

    if 'rmdir' in message:
        return regex.rmdir(message)

    if 'mkdir' in message:
        return regex.mkdir(message)

    if 'rename' in message:
        return regex.rename(message)


def pid_user_ip_extractor(dicit_pids):
    for pid in dicit_pids:
        user = ''
        ip = ''
        for dict_log_line in dicit_pids[pid]:
            if 'Accepted password for' in dict_log_line['message']:
                user = regex.user(dict_log_line['message'])
                ip = regex.ip(dict_log_line['message'])
                break
            if 'session opened for local user' in dict_log_line['message']:
                user = regex.user2(dict_log_line['message'])
                ip = regex.ip2(dict_log_line['message'])
                break
        for dict_log_line in dicit_pids[pid]:
            dict_log_line['user'] = user
            dict_log_line['ip'] = ip


def pid_processor(dict_pids):
    # Aggiunge ad ogni collezione (di pid) user e ip
    pid_user_ip_extractor(dict_pids)
    # Eseguo una copia dell'oggetto dict_pids
    # perche' operando su dict_collection modifico anche dict_pids
    dict_pids_copy = dict(dict_pids)
    for pid in dict_pids_copy:
        for dict_log_line in dict_pids_copy[pid]:
            # Reperisce le info principali della linea
            date = dict_log_line["date"]
            user = dict_log_line["user"]
            ip = dict_log_line["ip"]
            
            # Tiene solo conto di alcune azioni
            # ed estrae anche i file su cui ha operato
            action_matched = action_match(dict_log_line['message'])
            if action_matched is None:
                continue
            action = action_matched["action"]
            file = action_matched["file"]
            file2 = action_matched["file2"]

            write_csv(
                text='{},{},{},{},{},{},{}\n'.format(date, user, ip, pid, action, file, file2),
                overwrite=False
            )
        # Svuoto il contenuto della chiave una volta scritto il CSV
        # per liberare la RAM
        dict_pids_copy[pid] = []
        # Elimina la chiave una volta scritto il CSV
        # per liberare la RAM
        del dict_collection[pid]
        


def write_csv(text, overwrite):
    mode = 'w' if overwrite else 'a+'
    with open('out.csv', mode) as file:
        file.write(text)


if __name__ == '__main__':
    # Crea il file CSV
    write_csv(
        text='Month,Day,Time,User,IP,PID,Action,File,File New (rename only)\n',
        overwrite=True
    )
    
    # Per ogni file
    for file in get_full_logs_path(logs_path):
        # Per ogni linea di ogni file
        for line in get_lines(file):
            # Suddivide ogni linea in data, pid, messaggio
            dict_log_line = regex.line_parser(line)
            if dict_log_line is not None:
                pid_collector(dict_log_line)
        # Elabora i pid che non hanno concluso la sessione
        # gli ultimi rimasti per file
        pid_processor(dict_collection)
