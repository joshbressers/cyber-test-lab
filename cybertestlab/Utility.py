#!/usr/bin/env python

import os
import subprocess

class CTLUtils(object):
    def __init__(self, debug=False):

        self.debug = debug
	# Do nothing exciting (yet)


    @staticmethod
    def run_command(cmd, description):
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            results = p.communicate()[0]
        except Exception as e:
            raise Exception(description + ' failed: ' + str(e))
        return results

    @staticmethod
    def which(program):
        import os

        for path in os.environ["PATH"].split(os.pathsep):
            absolute_path = os.path.join(path, program)
            if CTLUtils.is_executable(absolute_path):
                return absolute_path

        return None

    @staticmethod
    def is_executable(absolute_path):
        if os.path.isfile(absolute_path) and \
                os.access(absolute_path, os.X_OK):
            return True
        else:
            return False

    @staticmethod 
    def find_elfs(path):

        find_results = []
        find = CTLUtils.which('find')
        grep = CTLUtils.which('grep')
        cmd = find + ' ' + path + \
              ' -type f -exec file {} \; | ' + grep + ' -i elf'
        find_results = CTLUtils.run_command(cmd, 'find elfs')

        elfs = []
        for result in filter(None, find_results.split('\n')):
            elfs.append(result.split(':')[0])

        if len(elfs) == 0:
            return None
        else:
            return filter(None, elfs)

    @staticmethod
    def mkdir_p(path):
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno == 17 and os.path.isdir(path):
                pass
            else:
                raise
