#!/usr/bin/env python

import os
import sys

import r2pipe
import timeout_decorator

from Utility import CTLUtils
from Analysis import Analysis

__author__ = 'Jason Callaway'
__email__ = 'jasoncallaway@fedoraproject.org'
__license__ = 'GNU Public License v2'
__version__ = '0.3'
__status__ = 'beta'


class CyberTestLab(object):
    def __init__(self, **kwargs):

        self.repo_dir = '/repo'
        if kwargs.get('repo_dir'):
            self.repo_dir = kwargs['repo_dir']

        self.swap_path = '/fedora_swap'
        if kwargs.get('swap_path'):
            self.swap_path = kwargs['swap_path']

        self.repo_list = ['fedora', 'updates']
        if kwargs.get('repo_list'):
            self.repo_list = kwargs['repo_list']

        self.hardening_check = CTLUtils.which('hardening-check')
        if kwargs.get('hardening_check'):
            self.hardening_check = kwargs['hardening_check']
        if not self.hardening_check:
            raise Exception('CyberTestLab: cannot find hardening-check')

        self.debug = False
        if kwargs.get('debug'):
            self.debug = kwargs['debug']

    def repo_sync(self, command):
        args = ''
        if 'reposync' in command:
            args = ' -p ' + self.repo_dir
        else:
            raise Exception('CyberTestLab: unsupported repo type: ' + command)
        sync_cmd = CTLUtils.which(command) + args
        r = CTLUtils.run_command(sync_cmd, 'syncing repos')

    def prep_swap(self):
        rm = CTLUtils.which('rm')
        cmd = rm + ' -Rf ' + self.swap_path + '/*'
        r = CTLUtils.run_command(cmd, 'clean up swap path')

    def prep_rpm(self, repo, rpm):
        cp = CTLUtils.which('cp')
        cmd = cp + ' ' + self.repo_dir + '/' + \
              repo + '/' + rpm + ' ' + \
              self.swap_path
        r = CTLUtils.run_command(cmd, 'cp rpm to swap_path')

        # crack the rpm open
        # cd = CTLUtils.which('cd')
        rpm2cpio = CTLUtils.which('rpm2cpio')
        cpio = CTLUtils.which('cpio')
        cmd = '(cd ' + self.swap_path + ' && ' + rpm2cpio + ' ' + \
              rpm + ' | ' + cpio + ' -idm 2>&1 >/dev/null)'
        r = CTLUtils.run_command(cmd, 'rpm2cpio pipe to cpio')

    def get_metadata(self, rpm):
        rpm_data = {}
        cmd = 'rpm -qip ' + self.swap_path + '/' + rpm
        # this is a list
        rpm_qip = CTLUtils.run_command(cmd, 'rpm -qip')

        if len(rpm_qip.split('Description :')) > 1:
            not_description, description = \
                rpm_qip.split('Description :')
            raw_metadata = not_description.split('\n')
            metadata = {}
            for line in raw_metadata:
                if line == '':
                    continue
                k, v = line.split(':', 1)
                metadata[k.rstrip()] = v
            metadata['Description'] = description
            rpm_data['spec_data'] = metadata
        else:
            rpm_data['Description'] = 'unable to parse `rpm -qip` output'

        return rpm_data

    def find_elfs(self):
        return CTLUtils.find_elfs(self.swap_path)

    def scan_elfs(self, rpm, elfs):

        analysis = Analysis(self.swap_path)
        scan_results = analysis.scan_elfs(elfs)
        for i in scan_results.keys():
            scan_results[i]['rpm'] = rpm
        return scan_results
