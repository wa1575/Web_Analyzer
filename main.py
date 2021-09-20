# -*- encoding: utf-8 -*-
import sys
import parsing, banlist, loggings, labeling

# 명령문 실행 
args = sys.argv[1]
# 전달인자 파싱 
parsing.Parsing(args).parsing_data()
# 시그니처 밴 리스트 출력
banlist.Banlist.banlist_create()
# 로깅 실행
loggings.Logging.logging_data()
# 원본 데이터에서 추출 
labeling.Labeling(args).labeling_data()