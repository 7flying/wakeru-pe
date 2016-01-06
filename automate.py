# -*- coding: utf-8 -*-
"""
Automates the dataset generation process.
"""
import subprocess
from sys import argv
from os import listdir
from os.path import isfile, join

HEADER = "@relation {0}\n@attribute code string\n@attribute $category$"+\
  " {{malware, goodware}}\n@data\n"
ROW = "'{0}',{1}\n"

def disassemble(path_to_file):
    """Disassembles the .text section of the given file.
    Errors go to stderr.txt, if so returns None."""
    error_file = open('stderr.txt', 'a')
    out = None
    try:
        out = subprocess.check_output(['./disass.sh', path_to_file],
                                      stderr=error_file)
    except:
        print " [ ERROR ] Error with sample %s" % (path_to_file)
    error_file.close()
    return out

def main(dataset_name, malware_path, goodware_path, count_samples=50):
    """Disassembles PE files on malware_path and goodware_path folders,
    generates an .arff with them."""
    with open(dataset_name, 'w') as dataset:
        dataset.write(HEADER.format(dataset_name))
        for class_, path in zip(['malware', 'goodware'],
                                 [malware_path, goodware_path]):
            count = 0
            for sample in listdir(path):
                print " [ INFO ] count: %d, processing sample %s, %s" % (count,
                                                                         sample,
                                                                         class_)
                if count > count_samples:
                    break
                if isfile(join(path, sample)):
                    dis = disassemble(join(path, sample))
                    dis = dis.strip()
                    if dis and len(dis) > 0:
                        dataset.write(ROW.format(dis, class_))
                        count += 1
            print " [ INFO ] Processed %d samples of class: '%s'" % (count,
                                                                     class_)

if __name__ == '__main__':
    if len(argv) == 4:
        main(argv[1], argv[2], argv[3])
    elif len(argv) == 5:
        main(argv[1], argv[2], argv[3], int(argv[4]))
    else:
        print "Usage:\n automate.py dataset_name malware_path" + \
          " goodware_path [samples_per_class]"
