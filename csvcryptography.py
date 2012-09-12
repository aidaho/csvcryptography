#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CSV cryptography - applies encryption and decryption routines
                   to a specified columns of a csv file.

Copyright (C) 2012 Sergey Frolov

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, version 3
of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""
import os
import sys
import csv
import copy
import hashlib
import optparse
import pycryptopp

version = '0.1'
long_help = '''CSV cryptography - applies AES CTR encryption and decryption routines
                   to a specified columns of a csv file.

usage: csvcryptography.py [options] file1 [dir1 file2 ...]

    You can supply any number of target files/dirs to this utility.

    Note that the directories will be processed recursively and CSV
files will be recognized by their contents rather than extension.

    Because the symmetric-key algorithm was used, there is no need to
explicitly specify current action (decryption or encryption). If data
was encrypted it will be decrypted and vice versa.

    AES CTV is a stream version of a corresponding block cipher, this
means that if you encrypted column 0, and later decided to encrypt
column 1 with same password, you cannot decrypt them both
simultaneously with -c 0,1 option, because they are a different streams.
Likewise, if couple columns were encrypted simultaneously, you cannot
decrypt them one by one, they are in the same stream now.

    It is perfectly ok to encrypt different columns of one file with
different passwords:
        csvcryptography.py -c 0 --password pass1 file
        csvcryptography.py -c 1 --password pass2 file

    Now the column 0 is encrypted with "pass1" password and column 1 with
"pass2". You can selectively decrypt first column:
        csvcryptography.py -c 0 --password pass1 file

    Others will be left in unaltered state: the second one left
encrypted. Now decrypt the second column:
        csvcryptography.py -c 1 --password pass2 file

    At this point of time file is reverted back to original unaltered
state. One more time take a note that encryption and decryption
commands for same targets are identical and column numeration starts
from zero.

    When using "-c" argument with multiple targets, make sure that all
of them have this many columns.


    KNOWN LIMITATIONS:

    As the CSV is not a format but only a lax convention, there are
many dialects of it. This software does not aim to support them all,
adapt code for yourself. While this software is considered
crossplatform, it silently assumes a few things most often found on
modern unix-based operation systems like UTF-8 encoding of input files
and presence or availability of Crypto++ library. Some effort might be
required in order to run it elsewhere. For example, UCS-2 encoding
will cause trouble to csv module.

                                                Sergey Frolov, 2012
                                            dunkan.aidaho@gmail.com

'''

## Options
parser = optparse.OptionParser(usage =
                               'usage: %prog [options] file1 [dir1 file2 ...]',
                               version=version)
parser.add_option('--long-help', dest='help', default=False,
                  action='store_true', help='show detailed usage info')
def check_columns(option, opt, value, parser):
    '''
    Column syntax checker helper for optparse.
    '''
    columns = value.split(',')
    for column in columns:
        if not column.isdigit():
            sys.exit('Syntax error: Bad column number: %s' % column)

parser.add_option('-c', '--columns', dest='columns', default=None,
                  help='target column(s). If there are more than one, use  '
                  'comma as a delimiter. For example: 0,1,3,6,9. Notice that '
                  'the numeration starts with zero. If this option is omitted '
                  'the whole file is assumed.', metavar='COLUMNS',
                  action='callback', callback=check_columns, type='string')
parser.add_option('--password', dest='password', default=None, type='string',
                  help='provide a password for encryption or decryption. '
                  'WARNING: do NOT use this option in an interactive shell: '
                  'your password will be stored in shell command history. '
                  'When this option is omitted user will be asked to provide '
                  'the password interactively.', metavar='PASSWORD')
parser.add_option('-n', '--not-really', dest='not_really', action='store_true',
                  default=False, help='print changes instead of doing them. '
                  'Implies "-v".')
parser.add_option('-v', '--verbose', dest='verbose', action='store_true',
                  default=None, help='show the name of a file being processed.')

(options, args) = parser.parse_args() # parse the command-line
if options.help:
    print long_help
    sys.exit()
if not bool(args): # look for targets ...
    sys.exit('Syntax error: No paths were given.')
for path in args: # ... and check them
    if not os.path.exists(path):
        sys.exit('Syntax error: target does not exist: %s' % path)
paths = map(os.path.abspath, args)
if not options.password:
    options.password = raw_input('Enter the password: ')
if options.not_really: # increase verbosity in dummy mode
    options.verbose = True
target_columns = []
if options.columns: # parse list of columns if any
    for col_number in options.columns.split(','):
        target_columns.append(int(col_number))

    
# Top-level functions
def crypto(string):
    '''
    Encrypts/decrypts string with global AES object "enigma".
    '''
    return enigma.process(string)

def crypto_init(password):
    '''
    Returns AES object instance initialised with provided password.
    '''
    hashed_key = hashlib.md5(password).digest() # hash password
    return pycryptopp.cipher.aes.AES(key=hashed_key) # use it as AES key

def crawler(paths):
    '''
    Unrolls recursively all directories in iterable to tuple with it contents.
    Leaves file paths unchanged
    '''
    unrolled_paths = []
    for path in paths:
        if os.path.isdir(path):
            subpaths = []
            for p in os.listdir(path):
                subpaths.append(path + '/' + p)
            for p in crawler(subpaths):
                unrolled_paths.append(p)
        else:
            unrolled_paths.append(path)
    return unrolled_paths

# Main logic
processed_files = 0
for target in crawler(paths):
    enigma = crypto_init(options.password)
    if options.verbose:
        print '\nProcessing file: %s\n' % os.path.abspath(target)
    try:
        csv_contents = []
        csvfile = open(target, 'rb')
        for line in csv.reader(csvfile):
            if not options.columns:
                newline = map(crypto, line)
            else:
                newline = copy.copy(line)
                for column in sorted(target_columns): # do not depend on user
                    newline[column] = crypto(line[column])
            csv_contents.append(newline)
        csvfile.close() # cleanup
    except csv.Error:
        print 'Error: file %s does not seem ' % os.path.abspath(target),
        print 'like valid CSV file, skipped'
        csvfile.close()
        continue
    if options.not_really: # print everything, change nothing
        for line in csv_contents:
            print line
        print
        continue
    else:
        csvfile = open(target, 'wb') # rewrite source file
        csvfile.truncate(0) # destroy contents
        csvwriter = csv.writer(csvfile)
        for line in csv_contents:
            csvwriter.writerow(line)
        csvfile.close()
        processed_files += 1
if not processed_files:
    print 'Nothing done'
else:
    print '%d file(s) was altered.' % processed_files

sys.exit()










