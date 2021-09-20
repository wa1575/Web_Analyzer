# -*- encoding: utf-8 -*-

import json
import sys
import urllib.parse


class Parsing :
    def __init__(self, argv):
        # self.args = sys.argv[1]
        self.args = argv

    def parse_uri(uri) :
        parsed = urllib.parse.urlparse(urllib.parse.unquote(uri))

        part = parsed.path.split('/')
        path = parsed.path
        fname = None
        ext = None
        if '.' in part[-1]:
            path = path[:-len(part[-1])]
            pt = part[-1].split('.')
            ext = pt[-1]
            fname = part[-1][:-len(pt[-1])-1]
        return path, fname, ext ,urllib.parse.parse_qs(parsed.query)

    def parsing_data(self):
        i = 1
        result = {}
        with open(self.args) as f:
            lines = f.readlines()
            for line in lines:
                try:
                    r = line.split(' ')
                    if r[3] > r[0] : # 일반적인 경우 
                        result[i] = {'IP': r[0],
                        'DATE': r[3][1:], 'METHOD': r[5][1:], 'PATH': None, 'FNAME': None, 'EXT' : None,
                                    'VERSION':r[7][:-1], 'STATUS':r[8], 'SIZE': r[9][:-1], 'ARGS' : None, 'URI' : r[6]}
                        result[i]['PATH'] , result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
                            =  Parsing.parse_uri(r[6])
                    else :
                        result[i] = {'IP': r[0],
                        'DATE': r[4][1:], 'METHOD': r[6][1:], 'PATH': None, 'FNAME': None, 'EXT' : None,
                                    'VERSION':r[8][:-1], 'STATUS':r[9], 'SIZE': r[10][:-1], 'ARGS' : None, 'URI' : r[7]}
                        result[i]['PATH'] , result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
                            =  Parsing.parse_uri(r[7])



                except IndexError as e: # 400에러 등 예외처리
                    r = line.split(' ')
                    if r[3] > r[0] :
                        result[i] = {'IP': r[0],
                        'DATE': r[3][1:], 'METHOD': "-", 'PATH': None, 'FNAME': None, 'EXT' : None,
                                    'VERSION':"-" , 'STATUS':r[6], 'SIZE': "-", 'ARGS' : None, 'URI' : ""}
                        result[i]['PATH'] , result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
                            =  Parsing.parse_uri("")
                    else :
                        result[i] = {'IP': r[0],
                        'DATE': r[4][1:], 'METHOD': "-", 'PATH': None, 'FNAME': None, 'EXT' : None,
                                    'VERSION':"-" , 'STATUS':r[7], 'SIZE': "-", 'ARGS' : None, 'URI' : ""}
                        result[i]['PATH'] , result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
                            =  Parsing.parse_uri("")

                i += 1 
        with open('data.json', 'w',encoding="utf-8") as fp:
            json.dump(result, fp, ensure_ascii=False, indent="\t")