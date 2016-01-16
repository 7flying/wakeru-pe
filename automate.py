# -*- coding: utf-8 -*-
"""
Automates the dataset generation process.
"""
import subprocess, re, ntpath, random, string, pefile, datetime
from sys import argv
from os import listdir
from os.path import isfile, join

HEADER = "@relation {0}\n@attribute code string\n@attribute $category$"+\
  " {{malware, goodware}}\n@data\n"
ROW = "'{0}',{1}\n"

# Keel header, put inst names and min-max count on {2}. All at {2}
# put comma separated inst names at {3}
HEADER_KEEL = "@relation {0}\n@attribute sections integer [{0}-{1}]\n" +\
  "@attribute avgentropy real [0.0, 8.0]\n{2}" +\
  "@attribute $class$ {malware, goodware}\n@inputs sections, avgentropy, {3}\n" +\
  "@outputs $class$\n@data\n"


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

def objdump(path_to_file, path_to_output_folder):
    error = False
    error_file = open('objdumerr.txt', 'a')
    filename = ntpath.basename(path_to_file)
    if not filename:
        filename = ''.join(random.choice(string.letters) for _ in range(15))
    output_file = open(join(path_to_output_folder, filename + ".hex"), 'w')
    try:
        subprocess.call(['objdump', '-d', path_to_file], stdout=output_file,
                        stderr=error_file)
    except:
        print " [ERROR] Disassembling sample {0}".format(path_to_file)
        error = True
    finally:
        output_file.close()
        error_file.close()
    return error

def objdump_all(path_to_folders, path_to_out_folders, max_samples):
    for in_folder, out_folder, maxi in zip(path_to_folders,
                                           path_to_out_folders, max_samples):
        count = 0
        for sample in listdir(in_folder):
            if count > maxi:
                break
            err = objdump(join(in_folder, sample), out_folder)
            if not err:
                count += 1
                print "[{0}/{1}] Processed: {2}".format(count, maxi, sample)
                

def get_mnemonics(path_to_file):
    """Returns a dict with the opcode mnemonic and number of times it has been
    used."""
    regex = r'(\s|\t)+\d+:(\s|\t)+([a-f0-9][a-f0-9]\s)+(\s|\t)+([a-zA-Z0-9.]+)'
    ret = {}
    with open(path_to_file, 'r') as fil:
        for line in fil:
            result = re.match(regex, line)
            if result:
                code = result.group(5)
                if ret.get(code) is None:
                    ret[code] = 0
                ret[code] += 1
    print ret
    return ret

def get_mnemonics_folders(folder_list, max_samples=5):
    mnemonics = []
    for folder in folder_list:
        count = 0
        for sample in listdir(folder):
            if count > max_samples:
                break
            if isfile(join(folder, sample)):
                ret = get_mnemonics(join(folder, sample))
                if len(ret.keys()):
                    mnemonics.append(ret)
                    count += 1
    return mnemonics

def get_pe_info(path_to_file):
    """Returns tuple with number of sections and their average entropy."""
    pe = None
    try:
        pe = pefile.PE(path_to_file)
    except:
        return (None, None)
    if pe:
        sections = len(pe.sections)
        avg_entro = 0
        if sections != 0:
            for section in pe.sections:
                avg_entro += section.get_entropy()
            avg_entro = avg_entro / sections
    return (sections, avg_entro)

def _get_set_mnemonics(path_to_file):
    regex = r'(\s|\t)+\d+:(\s|\t)+([a-f0-9][a-f0-9]\s)+(\s|\t)+([a-zA-Z0-9.]+)'
    ret = set()
    with open(path_to_file, 'r') as fil:
        for line in fil:
            result = re.match(regex, line)
            if result:
                ret.add(result.group(5))
    return ret

def _get_different_instructions(list_hex_folders, max_samples):
    ret = set()
    for folder in list_hex_folders:
        count = 0
        for sample in listdir(folder):
            if count >= max_samples:
                break
            if isfile(join(folder, sample)):
                ret.update(_get_set_mnemonics(join(folder,sample)))
    return ret

def gen_keel_arff(tuple_goodware, tuple_malware, max_samples=2):
    """Generates a keel arff, where tuple_<class> has: folder hex files,
    folder pe files, class name (goodware or malware).
    """
    time_format = "%H:%M"
    temp_time = datetime.datetime.now()
    print " [{0}] Process started.".format(temp_time.strftime(time_format))
    diff_inst = _get_different_instructions([tuple_goodware[0],
                                             tuple_malware[0]], max_samples)
    temp_time = datetime.datetime.now()
    print " [{0}] Num. different instructions: {1}".format(
        temp_time.strftime(time_format), len(diff_inst))
    
    

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
    get_mnemonics(argv[1])
    """
    mnemonics = get_mnemonics_folders(argv[1:])
    print mnemonics
    
    if len(argv) == 4:
        main(argv[1], argv[2], argv[3])
    elif len(argv) == 5:
        main(argv[1], argv[2], argv[3], int(argv[4]))
    else:
        print "Usage:\n automate.py dataset_name malware_path" + \
          " goodware_path [samples_per_class]"
    """
