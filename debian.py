#!/usr/bin/env python

import json
import os
import sys
import traceback

from datetime import datetime

from cybertestlab import CyberTestLab
from cybertestlab import Utility

__author__ = 'Jason Callaway'
__email__ = 'jasoncallaway@fedoraproject.org'
__license__ = 'GNU Public License v2'
__version__ = '0.3.1.9.3.1.6.4.9.0.7.q'
__status__ = 'gamma'


def main(argv):
    debug = True
    now = datetime.now()
    output_dir = sys.argv[1]
    repo_dir = sys.argv[2]
    swap_path = sys.argv[3]
    ctl = CyberTestLab.DEBTestLab(repo_dir,swap_path, debug=True)
    Utility.CTLUtils.mkdir_p(repo_dir)
    Utility.CTLUtils.mkdir_p(swap_path)

    for root, dirs, files in os.walk(repo_dir):
        for filename in files:
            if debug:
                print('+ ' + filename)
            results_dir = output_dir + '/' + filename[0]
            results_file = results_dir + '/' + filename + '.json'
            if not os.path.isfile(results_file):
                if debug:
                    print('++ analyzing ' + filename)
                ctl.prep_swap()
                try:
                    analyze(ctl, repo_dir, filename, results_dir, results_file)
                except Exception as e:
                    print('debian analysis failed on ' + filename)
                    traceback.print_exc()
                    continue


def analyze(ctl, repo_dir, filename, results_dir, results_file):

    deb_file = os.path.join(repo_dir, filename)
    ctl.prep_deb(deb_file)
    metadata = ctl.get_metadata(deb_file)
    elfs = ctl.find_elfs()
    if elfs:
        results = ctl.scan_elfs(filename, elfs)
        Utility.CTLUtils.mkdir_p(results_dir)
        with open(results_file, 'w') as f:
            json.dump({'metadata': metadata,
                       'results': results}, f, indent=4)
    else:
        Utility.CTLUtils.mkdir_p(results_dir)
        with open(results_file, 'w') as f:
            json.dump({'metadata': metadata,
                       'results': 'no elfs found'}, f, indent=4)


if __name__ == "__main__":
    main(sys.argv)
