import subprocess, shutil
from os import listdir, remove, _exists
import os
from os.path import isfile, join

#unzip files from a client with 7zip
def unzip(serial_number, pw):
    cmd = ['7z', 'x', serial_number + '.zip', '-o'+serial_number, '-p'+ pw]
    p = subprocess.Popen(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    p.communicate()

    folder = serial_number
    onlyfiles = [f for f in listdir(folder) if isfile(join(folder, f))]

    for f in onlyfiles:
        cmd = ['mv', folder+'/'+f, '.']
        p = subprocess.Popen(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        p.communicate()

    shutil.rmtree(folder)
    os.remove(os.path.join('.', serial_number + '.zip'))

#zip files from client with 7zip
def zzip(serial_number, pw):
    cmd = ['7z', 'a', serial_number + '.zip', '-p' + pw, '-y', serial_number+'*']
    p = subprocess.Popen(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    p.communicate()

    for fname in os.listdir('.'):
        if fname.startswith(serial_number) and not fname.endswith('.zip'):
            os.remove(os.path.join('.', fname))
