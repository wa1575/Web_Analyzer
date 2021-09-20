import string
import sys
import datetime
import numpy as np
import re


import json

#텍스트 출력 [디버깅용]
#label[1] = path 및 args 공격코드 감지 
#label[3] = args 및 ext 내 webshell 시그니처 탐지 
#label[4] = Blind sql injection 시그니처 탐지 
#label[5] = METHOD 이상 탐지  
#nowDate = datetime.datetime.now()
#sys.stdout = open(nowDate.strftime("%Y-%m-%d_%H%M")+ ".txt","a", -1, 'utf-8')

class Logging:
    # uri 쿼리 변수 길이 필터 - IQR 이상치 검출 알고리즘 적용
    def find_upper_lower_bound(data_list):
        temp = sorted(data_list)
        q1, q3 = np.percentile(temp, [25, 75])
        iqr = q3 - q1
        #길이 보정, 만개도 안되는 샘플의 이상치는 보정이 필요함  
        if len(temp) <= 10000:
            lower_bound = q1 - (1.5 * iqr) - 1
            upper_bound = q3 + (1.5 * iqr) + 1

        else : 
            lower_bound = q1 - (1.5 * iqr)
            upper_bound = q3 + (1.5 * iqr)


        return lower_bound, upper_bound


    def find_same_name(a):
        # 1단계: 각 이름이 등장한 횟수를 딕셔너리로 만듦
        name_dict = {}
        for name in a:                # 리스트 a에 있는 자료들을 차례로 반복
            if name in name_dict:     # 이름이 name_dict에 있으면
                name_dict[name] += 1  # 등장 횟수를 1 증가

            else:                     # 새 이름이면
                name_dict[name] = 1   # 등장 횟수를 1로 저장

        # 2단계: 만들어진 딕셔너리에서 등장 횟수가 2 이하인 것을 결과에 추가
        result = set()          # 결괏값을 저장할 빈 집합
        for name in name_dict:  # 딕셔너리 name_dict에 있는 자료들을 차례로 반복
            if name_dict[name] <= 2:
                result.add(name)
        return result     
    

    def logging_data():
        with open('data.json', encoding="utf-8") as data_file:
            data = json.load(data_file)
        with open('dict.json', encoding="utf-8") as dict_file:
            ban = json.load(dict_file)
    
        # 근본있게 파일로 만들어서 조회가능하게...
        #BAN LIST 출력 
        BAN = [ x for x in ban["Attack code"].values()]
        resultlist1 = []


        #쿼리문 파싱 결과 사이즈 
        args = []
        argslen = []
        sus_args = {}
        pas_args = {}

        resultlist2_1 = []
        resultlist2_2 = []


        # webshell 시그니처 탐지 
        shell_func = [ x for x in ban["Webshell code"].values()]
        shell_ext = [ x for x in ban["Webshell EXT type"].values()]
        resultlist3 = []

        #BSQL 인젝션 시느티처 탐지
        bsql_inj = [x for x in ban["Blind SQL INJECTION type"].values()]
        count = {}
        resultlist4 = []

        #METHOD 검사
        method_detc = [ x for x in ban["Inappropriate Method"].values()]
        resultlist5 = []

        #json으로 라벨링 결과 저장 
        label = {}
        p = re.compile('40.')
        f = re.compile('.*[.][;]$')

        # 1차 분류 개시 
        for i in data: 
            IP = data[i]["IP"]
            DATE = data[i]["DATE"]
            METHOD = data[i]["METHOD"]
            PATH = data[i]["PATH"]
            FNAME = data[i]["FNAME"]
            EXT = data[i]["EXT"]
            VERSION = data[i]["VERSION"]
            STATUS = data[i]["STATUS"]
            SIZE = data[i]["SIZE"]
            ARGS = data[i]["ARGS"] # dict라 전환 필요
            #ARGS KEY값 받기 = 변수명 
            argskey = ARGS.keys()
            args.extend(argskey)

            #printl = str(IP+" "+DATE+" "+METHOD+" "+str(PATH)+" "+str(FNAME)+"."+str(EXT)+" "+VERSION+" "+STATUS+" "+SIZE+ " "+str(ARGS))
            printl = "" +i
            if p.match(STATUS) : #상태가 400번대인건 무시
                pass
            else : 
                # Method를 보고 부적절한 양식이 있으면 결과에 추가
                for format in method_detc :
                    if METHOD.find(format) > 0 :
                        resultlist5.append(printl)

                # BAN 리스트와 비교해서 공격코드가 있으면 결과에 추가하기
                for format in BAN: #=ps%26제외 
                    if PATH.find(format) > 0:
                        resultlist1.append(printl)
                    if str(ARGS).find(format) > 0:
                        resultlist1.append(printl)

                # shell 리스트와 비교해서 웹 쉘 시그니처가 있으면 결과에 추가하기
                for format in shell_func:
                    if str(ARGS).find(format) > 0:
                        resultlist3.append(printl)
                    if FNAME == 'cmd' and str(EXT) == 'exe':
                        resultlist3.append(printl)
                # .jpg;.cer -> ; 뒷부분을 못읽는 옛날 취약점 공격 
                for format in shell_ext:
                    if METHOD == 'POST' or METHOD == 'PUT':
                        if f.match(str(FNAME)) and str(EXT).find(format) > 0:
                            resultlist3.append(printl)
                # BlindSQL 리스트와 비교해서 블라인드 SQL 탐지, 우선 시그니처 탐지
                for format in bsql_inj:
                    if str(ARGS).find(format) > 0: 
                        if STATUS == "500" or STATUS == "200" :
                            resultlist4.append(printl)


        #label[1] = { "Detecting Attack Code": resultlist1 }
        label.setdefault(1, []).extend(resultlist1)
        #label[2], Detecting Webshell Signature
        label.setdefault(2, []).extend(resultlist3)
        #label[3], Detecting Blind SQL Injection 
        label.setdefault(3, []).extend(resultlist4)
        #label[4], Detecting Inappropriate Method 
        label.setdefault(4, []).extend(resultlist5)


        with open('label.json', 'w', encoding="utf-8") as fp:
            json.dump(label, fp, ensure_ascii=False, indent="\t")







    

        
