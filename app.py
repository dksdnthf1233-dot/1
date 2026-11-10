# -*- coding: utf-8 -*-
"""
🦺 현장 안전 판독 (Streamlit + OpenAI GPT-4o Vision)  ── 한 파일 완성본

[기능]
 1) 스마트폰 카메라 촬영 / 갤러리 업로드
 2) GPT-4o가 사진 속 위험요인 판독 (추락·전도·낙하·감전·화재 등)
 3) 위험 위치를 사진에 번호 박스로 표시하고, 아래 3가지를 표로 출력
      ① 위반 소지 '산업안전보건기준에 관한 규칙' 조항
      ② 관련 'KOSHA GUIDE'
      ③ 현장 즉시 조치
 4) 법령·지침이 개정되면 코드 수정 없이 업데이트 (「🔄 기준 업데이트」 탭)
      - 산안칙: 국가법령정보센터 OPEN API로 개정 감지 + 조문 동기화
      - KOSHA GUIDE: 표 편집 / CSV·JSON 업로드 / 구번호→신번호 연결
      - 변경 전 자동 백업, 이력 기록, 복원

[설치]   pip install -U streamlit openai pillow
[실행]   streamlit run safety_ai_app.py
[키 설정] (방법 중 하나)
   · 앱 화면 상단 '설정'에 OpenAI API 키 붙여넣기 (가장 쉬움, 세션에만 저장)
   · 환경변수 OPENAI_API_KEY
   · .streamlit/secrets.toml 에
        OPENAI_API_KEY = "sk-..."
        LAW_OC         = "국가법령정보 OPEN API 인증키(OC)"   # 선택: 법령 자동 동기화용
        ADMIN_PASSWORD = "관리자 비밀번호"                    # 권장: 기준 업데이트 탭 보호

[주의] AI 판독은 안전관리자를 돕는 참고 도구입니다. 법 위반 여부의 최종 판단은
       현행 법령 원문(국가법령정보센터)과 KOSHA GUIDE 최신본으로 확인하세요.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import io
import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path

import openai
import pandas as pd
import requests
import streamlit as st
from openai import OpenAI
from PIL import Image, ImageDraw, ImageFont, ImageOps

# ═════════════════════════════════════════════════════════════════════
# 1. 기본 설정
# ═════════════════════════════════════════════════════════════════════
APP_DIR = Path(__file__).resolve().parent
KB_DIR = APP_DIR / "kb"                      # 기준 데이터 폴더 (자동 생성)
KB_PATH = KB_DIR / "safety_kb.json"          # 법령·지침·위험요인 데이터
BACKUP_DIR = KB_DIR / "backup"
LOG_PATH = KB_DIR / "changelog.jsonl"

LAW_NAME = "산업안전보건기준에 관한 규칙"
LAW_API = "https://www.law.go.kr/DRF"
LAW_PAGE = "https://www.law.go.kr/법령/산업안전보건기준에관한규칙"
KOSHA_PORTAL = "https://portal.kosha.or.kr"

MAX_SIDE = 1568                              # AI에 보낼 사진의 긴 변(px)
SEV_COLOR = {"높음": "#B42318", "중간": "#B54708", "낮음": "#175CD3"}
SEV_ORDER = {"높음": 0, "중간": 1, "낮음": 2}

# ═════════════════════════════════════════════════════════════════════
# 2. 초기(시드) 기준 데이터
#    - 처음 실행할 때 kb/safety_kb.json 으로 저장됩니다. 이후에는 이 파일이 기준입니다.
#    - verified=True : 조문 번호·제목을 웹에서 확인한 항목 / False : 동기화로 검증 필요
#    - 조문 '요지'는 참고용 요약입니다. 원문과 다를 수 있으니 반드시 원문을 확인하세요.
# ═════════════════════════════════════════════════════════════════════
_NOTE_OLD = ("2026.1월 공단의 KOSHA GUIDE 437건 정비(신규 번호체계)로 통합·대체됐을 수 있음. "
             "포털에서 최신 번호를 확인해 '대체 번호'를 입력하세요.")

_RULES = [  # (조항, 제목, 요지, 검증여부)
    ("제13조", "안전난간의 구조 및 설치요건",
     "상부난간대(바닥면 90cm 이상)·중간난간대·발끝막이판(10cm 이상)·난간기둥으로 구성하고 100kg 이상 하중에 견디는 구조로 설치", True),
    ("제14조", "낙하물에 의한 위험의 방지",
     "낙하물방지망·수직보호망·방호선반 설치, 출입금지구역 설정, 보호구 착용 등 조치(방지망·방호선반은 10m 이내마다, 내민 길이 2m 이상, 수평면 20~30도)", True),
    ("제20조", "출입의 금지 등",
     "추락·낙하 등 위험이 있는 장소에는 관계자 외 출입을 금지하고 그 취지를 표지 등으로 알릴 것(해당 호는 원문 확인)", True),
    ("제24조", "사다리식 통로 등의 구조",
     "견고한 구조, 발판 간격 일정 유지, 사다리 상단은 걸쳐놓은 지점에서 60cm 이상 올라오게 설치 등", False),
    ("제32조", "보호구의 지급 등",
     "추락·낙하 위험 작업 등에서 작업조건에 맞는 보호구(안전모·안전대·안전화 등)를 작업자 수 이상 지급하고 착용시킬 것", True),
    ("제38조", "사전조사 및 작업계획서의 작성 등",
     "별표 4에 해당하는 작업(차량계 건설기계, 중량물 취급 등)은 사전조사 후 작업계획서를 작성하고 그에 따라 작업", True),
    ("제39조", "작업지휘자의 지정",
     "작업계획서에 따라 작업을 지휘하는 작업지휘자를 지정(대상 작업은 원문 확인)", True),
    ("제42조", "추락의 방지",
     "추락 위험 장소에서는 작업발판 설치 → 곤란하면 추락방호망 → 곤란하면 안전대 착용 등 필요한 조치", True),
    ("제43조", "개구부 등의 방호 조치",
     "작업발판·통로 끝, 개구부의 추락 위험 장소에 안전난간·울타리·수직형 추락방망·덮개 설치. 곤란하면 추락방호망, 그것도 곤란하면 안전대 착용", True),
    ("제44조", "안전대의 부착설비 등",
     "추락 위험 높이 2m 이상 장소에서 안전대를 착용시킨 경우 안전하게 걸 수 있는 설비(구명줄·고정점 등)를 설치하고 이상 유무를 점검", True),
    ("제56조", "작업발판의 구조",
     "작업발판 폭 40cm 이상, 발판재료 사이 틈 3cm 이하, 추락 위험 장소에는 안전난간 설치, 발판재료는 둘 이상의 지지물에 고정", True),
    ("제57조", "비계 등의 조립·해체 및 변경",
     "비계 조립·해체·변경 시 관계자 외 출입금지, 악천후 시 작업 중지, 관리감독자 지휘, 추락 방지 조치 등", True),
    ("제68조", "이동식비계",
     "바퀴 브레이크 등 고정 + 아웃트리거(전도방지용 지지대) 설치, 승강용 사다리 견고 설치, 최상부 작업 시 안전난간 설치, 작업발판 최대적재하중 250kg 이내 등", True),
    ("제186조", "고소작업대 설치 등의 조치",
     "고소작업대는 바닥과 수평 유지, 갑작스러운 이동 방지를 위해 아웃트리거 또는 브레이크 등을 확실히 사용 등(원문 확인)", True),
    ("제241조", "화재위험작업 시의 준수사항",
     "용접·용단 등 화재위험작업 시 불티 비산방지 조치, 가연물 제거·방염, 소화기 비치 등", False),
    ("제301조", "전기 기계·기구 등의 충전부 방호",
     "충전부는 감전 방지를 위해 절연·덮개·울타리 등으로 방호", False),
    ("제302조", "전기 기계·기구의 접지",
     "누전 시 감전 위험이 있는 전기 기계·기구의 금속제 외함 등은 접지", False),
    ("제304조", "누전차단기에 의한 감전방지",
     "물기·도전성이 높은 장소 등에서 사용하는 이동형·휴대형 전기 기계·기구에는 누전차단기 설치", False),
    ("제2편 제1장 제9절(양중기)", "크레인 등 양중기의 위험 방지",
     "크레인·이동식크레인 등 양중기의 방호장치, 과부하 방지, 작업 시 조치 등(조항별 원문 확인)", True),
    ("제2편 제4장 제2절(굴착작업 등의 위험방지)", "굴착작업 등의 위험방지",
     "굴착작업 전 사전조사·작업계획서, 굴착면 기울기 준수, 흙막이 지보공 설치, 굴착기계 접근 통제 등(조항별 원문 확인)", True),
]

_GUIDES = [  # (코드, 제목, 상태, 비고)
    ("D-C-7-2026", "비계 구조 및 안전작업에 관한 기술지원규정", "현행", ""),
    ("A-G-20-2026", "그레이팅 설치 등에 관한 기술지원규정", "현행", ""),
    ("A-G-12-2026", "보호구 관련 기술지원규정 (정확한 명칭은 포털에서 확인)", "현행", ""),
    ("B-M-34-2026", "크레인 안전작업에 관한 기술지원규정", "현행", ""),
    ("B-E-12-2026", "전기작업안전에 관한 기술지원규정", "현행", ""),
    ("A-G-14-2026", "용접·용단 작업 시 화재예방에 관한 기술지원규정", "현행", ""),
    ("D-C-1-2025", "흙막이공사에 대한 기술지원규정", "현행", ""),
    ("D-C-4-2025", "굴착기 안전보건작업 기술지원규정", "현행", ""),
    ("D-C-5-2025", "굴착면 안전기울기 기준에 관한 기술지원규정", "현행", ""),
    ("D-C-11-2026", "굴착공사 관련 기술지원규정 (정확한 명칭은 포털에서 확인)", "현행", ""),
    ("C-26-2017", "낙하물 방지망 설치 지침", "확인필요", _NOTE_OLD),
    ("C-29-2017", "수직보호망 설치 지침", "확인필요", _NOTE_OLD),
    ("C-31-2017", "추락방망 설치지침", "확인필요", _NOTE_OLD),
    ("C-69-2012", "이동식 크레인 안전보건작업 지침", "확인필요", _NOTE_OLD),
    ("C-74-2015", "건설공사의 고소작업대 안전보건작업 지침", "확인필요", _NOTE_OLD),
    ("M-155-2023", "이동식 고소작업대의 선정과 안전관리에 관한 기술지침", "확인필요", _NOTE_OLD),
]

_HAZARDS = [  # (id, 이름, 기본심각도, 키워드, 조항들, 지침들, 즉시조치들)  ※ 조치 문장에 세미콜론(;) 금지
    ("H-MSCAFF-OUTRIGGER", "이동식비계 아웃트리거·바퀴 고정(브레이크) 미설치", "높음",
     ["이동식비계", "롤링타워", "바퀴", "브레이크", "아웃트리거", "전도방지 지지대"],
     ["제68조", "제42조"], ["D-C-7-2026"],
     ["비계 위 작업자를 즉시 안전하게 내리고 작업을 중지한다",
      "바퀴 브레이크(잠금)를 모두 체결하고 아웃트리거(전도방지용 지지대)를 전부 설치해 지면에 밀착시킨다",
      "바닥의 경사·침하·돌출물을 확인하고 필요하면 견고한 구조물에 고정한다",
      "관리감독자가 전도 방지 상태를 확인한 뒤 작업을 재개한다"]),
    ("H-MSCAFF-TOPRAIL", "이동식비계 최상부 안전난간·승강설비·적재하중 불량", "높음",
     ["이동식비계", "최상부", "난간 없음", "사다리", "적재하중"],
     ["제68조", "제13조", "제56조"], ["D-C-7-2026"],
     ["최상부 작업 전 안전난간(상부·중간난간대, 발끝막이판)을 설치한다",
      "승강용 사다리를 견고하게 부착하고 비계 외부를 타고 오르는 행위를 금지한다",
      "난간을 딛고 서거나 발판 위에 받침대·사다리를 얹어 쓰는 작업을 금지한다",
      "작업발판 최대적재하중(250kg)을 넘지 않도록 인원·자재를 제한한다"]),
    ("H-FALL-HARNESS", "안전대 미착용·미체결(걸이 설비 없음)", "높음",
     ["안전대", "안전벨트", "안전그네", "생명줄", "구명줄", "고소", "미체결", "걸이"],
     ["제42조", "제44조", "제32조"], ["A-G-12-2026"],
     ["해당 작업을 즉시 중지하고 작업자를 안전한 위치로 이동시킨다",
      "안전그네를 올바르게 착용하고 죔 상태를 확인한 뒤 걸이를 구명줄·고정점에 체결한다",
      "체결할 고정점이 없으면 설치하거나 추락방호망 등 다른 추락방지 조치를 먼저 한다",
      "안전대·로프·훅의 마모와 손상을 점검하고 불량품은 교체한다"]),
    ("H-FALL-OPENING", "개구부 덮개·난간 미설치(바닥·슬래브·피트 개구부)", "높음",
     ["개구부", "슬래브", "피트", "맨홀", "덮개", "바닥 구멍", "엘리베이터 피트"],
     ["제43조", "제13조", "제42조"], [],
     ["개구부 주변 접근을 통제하고 '추락 위험' 표지를 부착한다",
      "안전난간(또는 울타리·수직형 추락방망)을 우선 설치하고 덮개를 쓸 경우 뒤집히거나 떨어지지 않게 고정한다",
      "덮개에는 개구부 표시를 하고 제거할 때는 관리감독자 승인을 받는다",
      "난간·덮개 설치가 곤란하면 추락방호망을 설치하거나 안전대를 체결한다"]),
    ("H-FALL-RAIL", "안전난간 미설치·불량(상·중간난간대, 발끝막이판 누락)", "높음",
     ["안전난간", "난간대", "발끝막이판", "작업대 끝", "옥상", "테두리", "단부"],
     ["제13조", "제43조", "제42조"], [],
     ["추락 위험 구간의 접근을 통제하고 작업을 일시 중지한다",
      "상부난간대(바닥에서 90cm 이상)·중간난간대·발끝막이판·난간기둥을 갖춘 안전난간을 설치한다",
      "체결부 풀림·변형·파손을 점검해 보수하고 작업 때문에 해체했다면 즉시 원상복구한다",
      "임시 해체가 필요한 작업이면 추락방호망 또는 안전대 체결을 병행한다"]),
    ("H-FALL-NET", "추락방호망 미설치(난간·작업발판 설치가 곤란한 추락 위험 구간)", "높음",
     ["추락방호망", "방망", "철골", "개방된 단부", "외부 작업"],
     ["제42조", "제43조"], ["C-31-2017"],
     ["추락 위험 작업을 중지하고 접근을 통제한다",
      "추락방호망을 작업면에 가깝게 설치하고 처짐과 고정 상태를 확인한다",
      "방망의 안전인증 표시와 노후·손상 여부를 확인한다",
      "방호망 설치가 곤란하면 안전대 착용·체결을 병행한다"]),
    ("H-PLATFORM", "작업발판 미설치·폭/틈/고정 불량", "높음",
     ["작업발판", "발판", "틈", "고정 안 됨", "비계", "외줄", "합판 발판"],
     ["제56조", "제57조", "제42조"], ["D-C-7-2026", "A-G-20-2026"],
     ["작업발판이 불량한 구간의 작업을 중지하고 접근을 통제한다",
      "발판 폭 40cm 이상, 발판재 틈 3cm 이하가 되도록 보완하고 둘 이상의 지지물에 고정한다",
      "발판 끝과 개구부에는 안전난간을 설치한다",
      "파손·부식된 발판재는 교체하고 적재하중을 초과하지 않게 한다"]),
    ("H-FALL-OBJECT", "낙하물 방지(방지망·방호선반·출입통제) 미흡", "높음",
     ["낙하물", "자재 적치", "공구", "상하 동시작업", "방호선반", "수직보호망"],
     ["제14조", "제20조", "제32조"], ["C-26-2017", "C-29-2017"],
     ["하부 통행·작업을 즉시 통제하고 출입금지구역을 설정해 표지한다",
      "낙하물방지망·수직보호망·방호선반을 설치하고 고정 상태를 확인한다",
      "상부 자재는 결속·정리하고 공구에는 낙하방지 끈을 사용한다",
      "하부 작업자는 안전모(턱끈 체결)를 착용한다"]),
    ("H-PPE-HELMET", "안전모·안전화 등 보호구 미착용", "중간",
     ["안전모", "안전화", "보호구", "미착용", "턱끈", "보안경"],
     ["제32조"], ["A-G-12-2026"],
     ["작업자에게 작업에 맞는 보호구(안전모 턱끈 체결, 안전화 등)를 즉시 착용시킨다",
      "보호구 지급 수량과 상태(파손·유효기간)를 점검한다",
      "관리감독자가 작업 전 착용 상태를 확인하고 TBM에서 착용 의무를 다시 교육한다"]),
    ("H-LADDER", "사다리 설치·사용 불량(미고정, 상단 돌출 부족, 최상부 사용)", "중간",
     ["사다리", "A형 사다리", "접이식", "미끄럼", "고정 안 됨"],
     ["제24조", "제42조"], [],
     ["사다리 사용을 중지하고 작업자를 안전하게 내려오게 한다",
      "하단은 미끄럼을 방지하고 상단은 걸친 지점에서 60cm 이상 올라오게 하여 묶어 고정한다",
      "접이식 사다리는 벌림 방지 장치를 완전히 잠근 뒤 사용하고 최상부에 올라서지 않는다",
      "높은 곳 작업은 사다리 대신 이동식비계·고소작업대 등 안전한 작업발판 사용을 검토한다"]),
    ("H-AWP-OUTRIGGER", "고소작업대 아웃트리거 미설치·지반/경사 불량", "높음",
     ["고소작업대", "시저리프트", "붐 리프트", "아웃트리거", "경사지", "지반"],
     ["제186조", "제38조"], ["M-155-2023", "C-74-2015"],
     ["작업대 위 인원을 안전하게 하강시키고 작업을 중지한다",
      "설치 지반의 경사·침하·연약 여부를 확인하고 바닥을 수평에 가깝게 정리한다",
      "아웃트리거를 완전히 전개하고 받침판을 설치한 뒤 수평을 확인한다",
      "정격하중·탑승 인원을 지키고 작업대 고정점에 안전대를 체결한다"]),
    ("H-CRANE-OUTRIGGER", "이동식크레인 아웃트리거 미설치·미확장·지반 불량", "높음",
     ["이동식크레인", "카고크레인", "크레인", "아웃트리거", "인양", "연약지반", "붐"],
     ["제2편 제1장 제9절(양중기)", "제38조", "제39조"], ["B-M-34-2026", "C-69-2012"],
     ["인양 작업을 즉시 중지하고 하물을 안전하게 내린 뒤 붐을 원위치한다",
      "아웃트리거를 규정 폭까지 완전히 전개하고 잭을 모두 접지시켜 수평을 확인한다",
      "연약지반이면 받침판·철판으로 보강하고 지반 지지력을 확인한다",
      "작업계획서(작업반경·정격하중·지반)를 확인하고 작업지휘자·신호수를 배치한다",
      "인양 반경 내 근로자 출입을 통제한다"]),
    ("H-EXCAVATION", "굴착면 붕괴 위험(기울기 과다·흙막이 미설치·가장자리 적치)", "높음",
     ["굴착", "터파기", "흙막이", "굴착면", "붕괴", "토사", "트렌치"],
     ["제2편 제4장 제2절(굴착작업 등의 위험방지)", "제38조"],
     ["D-C-5-2025", "D-C-1-2025", "D-C-11-2026", "D-C-4-2025"],
     ["굴착면 하부·주변 작업을 즉시 중지하고 근로자를 대피시킨다",
      "굴착면 기울기를 토질별 기준에 맞게 완화하거나 흙막이 지보공을 설치한다",
      "굴착 가장자리의 굴착토·자재 적치를 금지하고 건설기계 접근을 통제한다",
      "균열·용수·붕괴 징후를 점검하고 승강설비와 추락방지 난간을 설치한다",
      "작업 전 사전조사와 작업계획서를 확인한다"]),
    ("H-ELEC", "전기 충전부 노출·임시배선·접지·누전차단 불량", "높음",
     ["전선", "충전부", "임시배선", "분전반", "접지", "누전차단기", "피복 벗겨짐", "물기"],
     ["제301조", "제302조", "제304조"], ["B-E-12-2026"],
     ["전원을 차단(잠금·표지)하고 감전 위험 구역의 접근을 통제한다",
      "노출된 충전부와 손상된 피복은 절연·덮개로 방호하거나 교체하고 전기 자격자가 보수한다",
      "전기 기계·기구를 접지하고 누전차단기를 설치한다",
      "물기가 있는 곳과 바닥 배선은 방수·보호 조치를 하고 높이 가설한다"]),
    ("H-HOTWORK", "용접·용단 불티 비산·가연물·소화기·화재감시자 미비", "높음",
     ["용접", "용단", "불티", "가연물", "소화기", "화재감시자", "그라인더"],
     ["제241조"], ["A-G-14-2026"],
     ["용접·용단 작업을 중지하고 불티 비산 범위의 가연물을 제거하거나 방염포로 덮는다",
      "불티 비산방지 덮개·차단막을 설치한다",
      "소화기를 비치하고 화재감시자를 배치한다",
      "작업 종료 후에도 일정 시간 잔불 여부를 확인한다"]),
]


def build_seed() -> dict:
    now = datetime.now()
    return {
        "meta": {
            "kb_version": now.strftime("%Y.%m.%d-%H%M%S"),
            "updated_at": now.strftime("%Y-%m-%d %H:%M"),
            "law_name": LAW_NAME,
            "law_effective_date": "",       # 동기화 시 자동 입력 (YYYYMMDD)
            "law_promulgation_no": "",
            "law_synced_at": "",
            "note": "초기 시드 데이터입니다. 현행 원문과 대조한 뒤 사용하세요.",
        },
        "rules": [{"article": a, "title": t, "summary": s, "verified": v, "state": "",
                   "official_text": "", "text_hash": "", "law_title": ""} for a, t, s, v in _RULES],
        "guides": [{"code": c, "title": t, "status": s, "superseded_by": "", "url": "", "note": n}
                   for c, t, s, n in _GUIDES],
        "hazards": [{"id": i, "name": n, "severity": sv, "keywords": k, "rules": r, "guides": g, "actions": a}
                    for i, n, sv, k, r, g, a in _HAZARDS],
    }


# ═════════════════════════════════════════════════════════════════════
# 3. 기준 데이터(KB) 읽기·쓰기·백업
# ═════════════════════════════════════════════════════════════════════
def normalize_kb(kb: dict) -> dict:
    meta = kb.setdefault("meta", {})
    for k, v in {"kb_version": "", "updated_at": "", "law_name": LAW_NAME, "law_effective_date": "",
                 "law_promulgation_no": "", "law_synced_at": "", "note": ""}.items():
        meta.setdefault(k, v)
    for r in kb.setdefault("rules", []):
        for k, v in {"title": "", "summary": "", "verified": False, "state": "",
                     "official_text": "", "text_hash": "", "law_title": ""}.items():
            r.setdefault(k, v)
    for g in kb.setdefault("guides", []):
        for k, v in {"title": "", "status": "확인필요", "superseded_by": "", "url": "", "note": ""}.items():
            g.setdefault(k, v)
    for h in kb.setdefault("hazards", []):
        for k, v in {"name": "", "severity": "중간", "keywords": [], "rules": [], "guides": [], "actions": []}.items():
            h.setdefault(k, v)
    return kb


def validate_kb(d) -> str:
    """문제가 있으면 오류 문구, 정상이면 빈 문자열."""
    if not isinstance(d, dict):
        return "최상위 구조가 JSON 객체가 아닙니다."
    for key, idk in (("rules", "article"), ("guides", "code"), ("hazards", "id")):
        items = d.get(key, [])
        if not isinstance(items, list):
            return f"'{key}'는 목록이어야 합니다."
        for x in items:
            if not isinstance(x, dict) or not str(x.get(idk, "")).strip():
                return f"'{key}' 항목에 '{idk}' 값이 없는 행이 있습니다."
    return ""


def check_refs(kb: dict) -> list[str]:
    """위험요인이 참조하는 조항·지침이 목록에 없는 경우를 찾습니다."""
    arts = {r["article"] for r in kb["rules"]}
    codes = {g["code"] for g in kb["guides"]}
    out = []
    for h in kb["hazards"]:
        out += [f"{h['id']}: 조항 '{a}' 없음" for a in h["rules"] if a not in arts]
        out += [f"{h['id']}: 지침 '{c}' 없음" for c in h["guides"] if c not in codes]
    return out


def _log(action: str, detail: str = ""):
    KB_DIR.mkdir(exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "action": action, "detail": detail}, ensure_ascii=False) + "\n")


def ensure_kb():
    KB_DIR.mkdir(exist_ok=True)
    BACKUP_DIR.mkdir(exist_ok=True)
    if not KB_PATH.exists():
        KB_PATH.write_text(json.dumps(build_seed(), ensure_ascii=False, indent=2), encoding="utf-8")
        _log("init", "시드 데이터로 초기화")


def load_kb() -> dict:
    ensure_kb()
    try:
        return normalize_kb(json.loads(KB_PATH.read_text(encoding="utf-8")))
    except Exception:
        # 파일이 손상된 경우: 손상본을 보관하고 시드로 복구
        shutil.copy2(KB_PATH, BACKUP_DIR / f"corrupt_{datetime.now():%Y%m%d_%H%M%S}.json")
        KB_PATH.write_text(json.dumps(build_seed(), ensure_ascii=False, indent=2), encoding="utf-8")
        _log("recover", "손상된 KB를 시드로 복구")
        return normalize_kb(json.loads(KB_PATH.read_text(encoding="utf-8")))


def save_kb(kb: dict, reason: str):
    """저장 전 자동 백업 → 임시 파일에 쓴 뒤 교체(저장 도중 끊겨도 파일이 깨지지 않음)."""
    ensure_kb()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if KB_PATH.exists():
        shutil.copy2(KB_PATH, BACKUP_DIR / f"safety_kb_{stamp}.json")
        for old in sorted(BACKUP_DIR.glob("safety_kb_*.json"), reverse=True)[40:]:
            old.unlink(missing_ok=True)
    kb["meta"]["kb_version"] = datetime.now().strftime("%Y.%m.%d-%H%M%S")
    kb["meta"]["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    tmp = KB_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(kb, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, KB_PATH)
    _log(reason, f"rules={len(kb['rules'])} guides={len(kb['guides'])} hazards={len(kb['hazards'])}")


def merge_kb(old: dict, new: dict) -> dict:
    out = json.loads(json.dumps(old))
    for key, idk in (("rules", "article"), ("guides", "code"), ("hazards", "id")):
        idx = {x[idk]: x for x in out[key]}
        for x in new.get(key, []):
            idx[x[idk]] = {**idx.get(x[idk], {}), **x}
        out[key] = list(idx.values())
    return normalize_kb(out)


def resolve_guide(code: str, gidx: dict):
    """구번호 → 신번호(superseded_by)를 따라가 최신 지침을 돌려줍니다. (지침, 원래코드 또는 None)"""
    g, seen = gidx.get(code), set()
    while g and g.get("superseded_by") and g["superseded_by"] in gidx and g["code"] not in seen:
        seen.add(g["code"])
        g = gidx[g["superseded_by"]]
    return g, (code if g and g["code"] != code else None)


# ═════════════════════════════════════════════════════════════════════
# 4. 법령 자동 동기화 (국가법령정보센터 OPEN API : open.law.go.kr)
# ═════════════════════════════════════════════════════════════════════
def _norm(s) -> str:
    return re.sub(r"[\s·ㆍ.,()\[\]「」'\"-]", "", str(s or ""))


def _flatten(node) -> list[str]:
    """조문 JSON(조문내용·항·호·목)에서 글자만 순서대로 모읍니다."""
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k.endswith("내용") or k in ("항", "호", "목"):
                out += _flatten(v)
    elif isinstance(node, list):
        for it in node:
            out += _flatten(it)
    elif isinstance(node, str) and node.strip():
        out.append(node.strip())
    return out


def _law_get(endpoint: str, params: dict, timeout: int) -> dict:
    r = requests.get(f"{LAW_API}/{endpoint}", params=params, timeout=timeout)
    r.raise_for_status()
    try:
        return r.json()
    except ValueError:
        raise RuntimeError("API 응답이 JSON이 아닙니다. 인증키(OC) 값과 open.law.go.kr 에서의 "
                           "IP·도메인 등록 여부를 확인하세요.")


def law_latest(oc: str) -> dict:
    data = _law_get("lawSearch.do", {"OC": oc, "target": "law", "type": "JSON",
                                     "query": LAW_NAME, "display": 20}, 20)
    items = (data.get("LawSearch") or {}).get("law") or []
    if isinstance(items, dict):
        items = [items]
    for it in items:
        if _norm(it.get("법령명한글")) == _norm(LAW_NAME):
            return {"mst": str(it.get("법령일련번호", "")), "effective": str(it.get("시행일자", "")),
                    "promulgation": str(it.get("공포일자", "")), "no": str(it.get("공포번호", "")),
                    "kind": str(it.get("제개정구분명", ""))}
    raise ValueError("검색 결과에 '산업안전보건기준에 관한 규칙'이 없습니다. 인증키(OC)를 확인하세요.")


def law_articles(oc: str, mst: str) -> dict:
    data = _law_get("lawService.do", {"OC": oc, "target": "law", "MST": mst, "type": "JSON"}, 60)
    units = ((data.get("법령") or {}).get("조문") or {}).get("조문단위") or []
    if isinstance(units, dict):
        units = [units]
    arts = {}
    for u in units:
        if u.get("조문여부") != "조문":
            continue
        no, br = str(u.get("조문번호", "")).strip(), str(u.get("조문가지번호", "")).strip()
        key = f"제{no}조" + (f"의{br}" if br else "")
        arts[key] = {"title": str(u.get("조문제목") or "").strip(), "text": "\n".join(_flatten(u))}
    if not arts:
        raise ValueError("조문을 읽지 못했습니다. API 응답 형식을 확인하세요.")
    return arts


def sync_law(kb: dict, oc: str) -> dict:
    """KB의 각 조항을 현행 법령과 대조해 제목·원문·변경 여부를 갱신하고 결과 보고서를 돌려줍니다."""
    info = law_latest(oc)
    arts = law_articles(oc, info["mst"])
    rep = {"info": info, "ok": 0, "changed": [], "missing": [], "title_mismatch": [], "skipped": []}
    for r in kb["rules"]:
        a = r["article"]
        if not re.fullmatch(r"제\d+조(의\d+)?", a):
            rep["skipped"].append(a)             # '제2편 제1장 …' 같은 장·절 단위는 자동 대조 제외
            continue
        cur = arts.get(a)
        if not cur:
            r["state"], r["verified"] = "미발견(삭제·이동 확인)", False
            rep["missing"].append(a)
            continue
        new_hash = hashlib.sha1(cur["text"].encode("utf-8")).hexdigest()
        old_hash = r.get("text_hash", "")
        r["official_text"], r["law_title"] = cur["text"][:3000], cur["title"]
        if _norm(cur["title"]) != _norm(r["title"]):
            r["state"], r["verified"] = "제목 불일치(개정 확인)", False
            rep["title_mismatch"].append((a, r["title"], cur["title"]))
        elif old_hash and old_hash != new_hash:
            r["state"], r["verified"] = "조문 변경(요지·조치 재검토)", True
            rep["changed"].append(a)
        else:
            if not str(r.get("state", "")).startswith("조문 변경"):   # 재검토 표시는 사람이 지울 때까지 유지
                r["state"] = ""
            r["verified"] = True
            rep["ok"] += 1
        r["text_hash"] = new_hash
    kb["meta"].update({"law_effective_date": info["effective"], "law_promulgation_no": info["no"],
                       "law_synced_at": datetime.now().strftime("%Y-%m-%d %H:%M")})
    return rep


@st.cache_data(ttl=6 * 3600, show_spinner=False)
def cached_law_latest(oc: str) -> dict:
    try:
        return law_latest(oc)
    except Exception as e:  # 네트워크·인증 오류는 조용히 무시(배너만 생략)
        return {"error": str(e)}


# ═════════════════════════════════════════════════════════════════════
# 5. 사진 처리 · AI 판독 · 결과 정리
# ═════════════════════════════════════════════════════════════════════
def prepare_image(raw: bytes):
    """휴대폰 사진의 회전 정보(EXIF)를 바로잡고, 크기를 줄여 JPEG로 변환합니다."""
    img = ImageOps.exif_transpose(Image.open(io.BytesIO(raw))).convert("RGB")
    img.thumbnail((MAX_SIDE, MAX_SIDE), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=88)
    return img, buf.getvalue()


SYSTEM_PROMPT = """당신은 건설·제조 현장 산업안전 전문가입니다. 업로드된 현장 사진에서 '눈으로 확인되는' 산업재해 위험요인만 판독합니다.

[원칙]
1. 사진에서 확인되지 않는 사항은 추측하지 말고 not_assessable에 적습니다. (예: 안전대 걸이 연결부가 가려져 보이지 않음)
2. 각 위험요인은 사용자 메시지의 [위험요인 카탈로그]에서 가장 알맞은 id를 kb_id로 고릅니다. 맞는 항목이 없으면 kb_id는 null로 두고, 확실한 경우에만 ai_suggested_article에 '산업안전보건기준에 관한 규칙' 조항(예: 제OO조 제목)을 적습니다. 조항·지침 번호를 지어내지 마세요. 모르면 빈 문자열입니다.
3. 같은 위험요인을 중복 보고하지 않습니다. 특정 근로자를 식별하거나 비난하는 표현은 쓰지 않습니다.
4. bbox는 사진 왼쪽 위를 (0,0), 오른쪽 아래를 (1000,1000)으로 하는 [x_min, y_min, x_max, y_max] 정수 좌표이며, 위험 부위를 감싸는 가장 작은 사각형입니다. 위치를 특정할 수 없으면 null입니다.
5. severity는 "높음"(추락·전도·감전·붕괴 등 사망·중상 직결), "중간", "낮음" 중 하나입니다. confidence는 0~1 사이 숫자입니다.
6. evidence는 사진에서 무엇이 보여 그렇게 판단했는지 한 문장으로 씁니다.
7. site_specific_action은 이 사진 상황에 맞는 추가 조치 1~2개(짧은 문장 목록)입니다. 카탈로그의 기본 조치와 중복하지 않습니다.
8. 사진이 흐리거나 어둡거나 가려져 판독이 어려우면 image_issues에 적습니다. 위험요인이 없으면 hazards는 빈 배열입니다.

반드시 아래 JSON 형식으로만 답하세요.
{
  "scene_summary": "사진 속 작업·상황 한두 문장",
  "image_issues": ["판독을 어렵게 하는 사진 문제"],
  "hazards": [
    {
      "title": "위험요인 이름(구체적으로)",
      "kb_id": "카탈로그 id 또는 null",
      "ai_suggested_article": "kb_id가 null일 때만, 확실한 경우 조항",
      "severity": "높음|중간|낮음",
      "confidence": 0.0,
      "evidence": "사진에서 확인되는 근거 한 문장",
      "bbox": [0, 0, 0, 0],
      "site_specific_action": ["이 사진 상황에 맞는 추가 조치"]
    }
  ],
  "not_assessable": ["사진만으로 판단할 수 없는 항목"]
}"""


def parse_json(text: str) -> dict:
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip())
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", t, re.S)
        if not m:
            raise
        return json.loads(m.group(0))


def analyze_image(api_key: str, model: str, jpg: bytes, kb: dict, memo: str) -> dict:
    catalog = "\n".join(f"- {h['id']} | {h['name']} | 키워드: {', '.join(h['keywords'])}" for h in kb["hazards"])
    user_text = (f"[작업 메모] {memo.strip() or '없음'}\n\n[위험요인 카탈로그]\n{catalog}\n\n"
                 "위 사진을 판독해 JSON으로만 답하세요.")
    b64 = base64.b64encode(jpg).decode()
    client = OpenAI(api_key=api_key, timeout=90, max_retries=2)
    resp = client.chat.completions.create(
        model=model, temperature=0.1, max_tokens=2500,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": [
                {"type": "text", "text": user_text},
                {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}", "detail": "high"}},
            ]},
        ],
    )
    msg = resp.choices[0].message
    if not msg.content:
        raise ValueError("AI가 이 사진에 대한 응답을 거부했습니다. 다른 사진으로 시도하세요.")
    return parse_json(msg.content)


def clean_bbox(b):
    try:
        x1, y1, x2, y2 = [float(v) for v in b]
    except Exception:
        return None
    if max(x1, y1, x2, y2) <= 1.0:                     # 0~1 비율로 답한 경우 보정
        x1, y1, x2, y2 = [v * 1000 for v in (x1, y1, x2, y2)]
    x1, x2, y1, y2 = *sorted((x1, x2)), *sorted((y1, y2))
    x1, y1, x2, y2 = [max(0.0, min(1000.0, v)) for v in (x1, y1, x2, y2)]
    return None if (x2 - x1) < 15 or (y2 - y1) < 15 else [x1, y1, x2, y2]


def normalize_hazards(result: dict, kb: dict) -> list[dict]:
    hidx = {h["id"]: h for h in kb["hazards"]}
    out = []
    for h in result.get("hazards") or []:
        if not isinstance(h, dict):
            continue
        kid = h.get("kb_id") if isinstance(h.get("kb_id"), str) else None
        e = hidx.get(kid) if kid else None                   # KB에 없는 id를 지어냈다면 미등록 처리
        sev = h.get("severity") if h.get("severity") in SEV_COLOR else (e["severity"] if e else "중간")
        try:
            conf = max(0.0, min(1.0, float(h.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
        acts = h.get("site_specific_action") or []
        acts = [acts] if isinstance(acts, str) else acts
        out.append({
            "title": str(h.get("title") or (e["name"] if e else "위험요인")).strip(),
            "kb_id": e["id"] if e else None,
            "ai_article": str(h.get("ai_suggested_article") or "").strip(),
            "severity": sev, "confidence": conf,
            "evidence": str(h.get("evidence") or "").strip(),
            "bbox": clean_bbox(h.get("bbox")),
            "site_actions": [str(a).strip() for a in acts if str(a).strip()][:2],
        })
    out.sort(key=lambda x: (SEV_ORDER[x["severity"]], -x["confidence"]))
    for i, h in enumerate(out, 1):
        h["no"] = i
    return out


def _font(size: int):
    for name in ("arialbd.ttf", "Arial Bold.ttf", "DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def annotate(img: Image.Image, hazards: list[dict]) -> Image.Image:
    """위험 위치에 번호 박스를 그립니다. (한글 폰트 없이도 동작하도록 사진에는 숫자만 표기)"""
    base = img.convert("RGBA")
    W, H = base.size
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    lw, r = max(3, round(min(W, H) / 160)), max(15, round(min(W, H) / 36))
    font = _font(int(r * 1.25))
    for h in hazards:
        if not h["bbox"]:
            continue
        x1, y1, x2, y2 = h["bbox"][0] / 1000 * W, h["bbox"][1] / 1000 * H, h["bbox"][2] / 1000 * W, h["bbox"][3] / 1000 * H
        col = tuple(int(SEV_COLOR[h["severity"]][i:i + 2], 16) for i in (1, 3, 5))
        d.rectangle([x1, y1, x2, y2], fill=col + (40,), outline=col + (255,), width=lw)
        cx, cy = min(max(x1, r), W - r), min(max(y1, r), H - r)
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=col + (255,), outline=(255, 255, 255, 255), width=max(2, lw // 2))
        s = str(h["no"])
        bb = d.textbbox((0, 0), s, font=font)
        d.text((cx - (bb[2] - bb[0]) / 2 - bb[0], cy - (bb[3] - bb[1]) / 2 - bb[1]), s, fill=(255, 255, 255, 255), font=font)
    return Image.alpha_composite(base, layer).convert("RGB")


def to_jpeg(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=90)
    return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════
# 6. 결과 표 만들기 (KB에서 조항·지침·조치를 가져와 조립)
# ═════════════════════════════════════════════════════════════════════
def esc(x) -> str:
    # 마크다운이 '$'를 수식으로 해석하지 않도록 함께 치환
    return html.escape(str(x if x is not None else ""), quote=True).replace("$", "&#36;")


def build_rows(hazards: list[dict], kb: dict) -> list[dict]:
    ridx = {r["article"]: r for r in kb["rules"]}
    gidx = {g["code"]: g for g in kb["guides"]}
    hidx = {h["id"]: h for h in kb["hazards"]}
    rows = []
    for h in hazards:
        e = hidx.get(h["kb_id"]) if h["kb_id"] else None
        rules = [ridx.get(a) or {"article": a, "title": "(규칙 목록에 없음)", "summary": "",
                                 "state": "KB 참조 오류", "official_text": ""} for a in (e["rules"] if e else [])]
        guides = []
        for c in (e["guides"] if e else []):
            g, old = resolve_guide(c, gidx)
            guides.append({**(g or {"code": c, "title": "(지침 목록에 없음)", "status": "확인필요", "note": ""}), "old": old})
        rows.append({"h": h, "entry": e, "rules": rules, "guides": guides,
                     "actions": list(e["actions"]) if e else []})
    return rows


def rows_to_html(rows: list[dict]) -> str:
    # ※ 마크다운이 들여쓰기·빈 줄을 코드/문단으로 오해하지 않도록 한 줄로 이어 붙입니다.
    o = ['<div class="hz-wrap"><table class="hz"><thead><tr><th>위험요인</th>'
         '<th>① 위반 소지 조항<small>산업안전보건기준에 관한 규칙</small></th>'
         '<th>② KOSHA GUIDE</th><th>③ 현장 즉시 조치</th></tr></thead><tbody>']
    for row in rows:
        h, e = row["h"], row["entry"]
        col = SEV_COLOR[h["severity"]]
        c1 = (f'<span class="no" style="background:{col}">{h["no"]}</span><b>{esc(h["title"])}</b><br>'
              f'<span class="sev" style="background:{col}">{h["severity"]}</span> '
              f'<span class="sm">신뢰도 {int(h["confidence"] * 100)}%</span>')
        if h["confidence"] < 0.5:
            c1 += '<span class="tag warn">재확인 필요</span>'
        if not h["bbox"]:
            c1 += '<span class="tag">위치 표시 불가</span>'
        if h["evidence"]:
            c1 += f'<div class="sm">{esc(h["evidence"])}</div>'
        if e:
            c2 = ""
            for r in row["rules"]:
                c2 += f'<div class="it"><b>{esc(r["article"])}</b> {esc(r["title"])}'
                if r.get("state"):
                    c2 += f'<span class="tag warn">⚠ {esc(r["state"])}</span>'
                elif not r.get("verified"):
                    c2 += '<span class="tag">원문 미검증</span>'
                if r.get("summary"):
                    c2 += f'<div class="sm">{esc(r["summary"])}</div>'
                if r.get("official_text"):
                    c2 += ('<details><summary>조문 원문 보기</summary><div class="sm">'
                           + esc(r["official_text"]).replace("\n", "<br>") + '</div></details>')
                c2 += '</div>'
        else:
            c2 = ('<div class="it"><span class="tag warn">KB 미등록</span> '
                  f'AI 제안(미검증): {esc(h["ai_article"]) or "해당 조항을 특정하지 못함"}'
                  '<div class="sm">관리자 검토 후 「기준 업데이트」에 등록하세요.</div></div>')
        c3 = ""
        for g in row["guides"]:
            c3 += f'<div class="it"><b>{esc(g["code"])}</b> {esc(g["title"])}'
            if g.get("old"):
                c3 += f'<span class="tag">구 {esc(g["old"])} 대체</span>'
            if g.get("status") != "현행":
                c3 += f'<span class="tag warn">⚠ {esc(g.get("status", "확인필요"))}</span>'
            c3 += '</div>'
        if not c3:
            c3 = (f'<div class="sm">등록된 지침 없음 — <a href="{KOSHA_PORTAL}" target="_blank" rel="noopener">'
                  'KOSHA 포털</a>에서 검색하세요.</div>')
        c4 = "".join(f"<li>{esc(a)}</li>" for a in row["actions"])
        c4 += "".join(f'<li><span class="tag">현장 보완</span> {esc(a)}</li>' for a in h["site_actions"])
        c4 = f"<ol>{c4}</ol>" if c4 else '<div class="sm">등록된 조치 없음 — 안전관리자 판단 필요</div>'
        o.append(f'<tr><td data-label="위험요인">{c1}</td><td data-label="① 위반 소지 조항 (산안칙)">{c2}</td>'
                 f'<td data-label="② KOSHA GUIDE">{c3}</td><td data-label="③ 현장 즉시 조치">{c4}</td></tr>')
    o.append("</tbody></table></div>")
    return "".join(o)


def rows_to_df(rows: list[dict], kb: dict) -> pd.DataFrame:
    meta, now = kb["meta"], datetime.now().strftime("%Y-%m-%d %H:%M")
    data = []
    for row in rows:
        h = row["h"]
        data.append({
            "번호": h["no"], "위험요인": h["title"], "심각도": h["severity"], "신뢰도": f'{int(h["confidence"] * 100)}%',
            "판단근거": h["evidence"],
            "위반소지조항": " / ".join(f'{r["article"]}({r["title"]})' for r in row["rules"]) or f'(KB 미등록) {h["ai_article"]}',
            "KOSHA_GUIDE": " / ".join(f'{g["code"]} {g["title"]}' for g in row["guides"]),
            "즉시조치": " | ".join(row["actions"] + h["site_actions"]),
            "KB버전": meta["kb_version"], "분석시각": now,
        })
    return pd.DataFrame(data)


# ═════════════════════════════════════════════════════════════════════
# 7. 화면 (모바일 최적화 CSS)
# ═════════════════════════════════════════════════════════════════════
CSS = """
<style>
.block-container{max-width:780px;padding:1rem .9rem 5rem}
footer{visibility:hidden}
.hdr{margin:0 0 .8rem}
.stripe{height:10px;border-radius:2px;background:repeating-linear-gradient(-45deg,#14181F 0 12px,#F7C600 12px 24px)}
.ttl{font-size:1.7rem;font-weight:800;letter-spacing:-.02em;margin:.6rem 0 .15rem;line-height:1.2}
.sub{opacity:.78;font-size:.95rem;margin:0}
.stButton>button,.stDownloadButton>button{width:100%;min-height:3rem;font-weight:700;border-radius:10px}
.stButton>button[kind="primary"],button[data-testid="stBaseButton-primary"]{background:#F7C600;color:#14181F;border:0}
.stButton>button[kind="primary"]:hover,button[data-testid="stBaseButton-primary"]:hover{background:#FFD83A;color:#14181F}
.stButton>button[kind="primary"] p,button[data-testid="stBaseButton-primary"] p{color:#14181F}
.sum{display:flex;gap:8px;flex-wrap:wrap;margin:.5rem 0 .8rem}
.chip{padding:6px 13px;border-radius:999px;font-weight:700;font-size:.9rem;color:#fff}
.note{border-left:5px solid #F7C600;padding:.4rem .8rem;margin:.4rem 0 .9rem;background:rgba(247,198,0,.12);border-radius:0 8px 8px 0;font-size:.92rem}
.hz-wrap{overflow-x:auto;margin:.3rem 0 1rem}
table.hz{border-collapse:collapse;width:100%;font-size:.9rem;line-height:1.5}
table.hz th{background:rgba(128,128,128,.2);text-align:left;padding:9px 10px;border:1px solid rgba(128,128,128,.4)}
table.hz th small{display:block;font-weight:400;opacity:.75}
table.hz td{vertical-align:top;padding:9px 10px;border:1px solid rgba(128,128,128,.4)}
table.hz ol{margin:0;padding-left:1.15rem}
table.hz li{margin-bottom:.3rem}
.no{display:inline-flex;width:1.7em;height:1.7em;border-radius:50%;color:#fff;justify-content:center;align-items:center;font-weight:800;margin-right:.45em;font-size:.9em}
.sev{color:#fff;padding:1px 8px;border-radius:6px;font-size:.78rem;font-weight:700}
.sm{font-size:.8rem;opacity:.82;margin-top:2px}
.it{margin-bottom:.65rem}
.tag{display:inline-block;font-size:.72rem;padding:0 7px;border-radius:6px;border:1px solid rgba(128,128,128,.6);margin-left:5px;vertical-align:1px}
.tag.warn{background:rgba(247,198,0,.28);border-color:#B54708}
table.hz details summary{cursor:pointer;font-size:.8rem;margin-top:3px}
@media (max-width:720px){
 table.hz thead{display:none}
 table.hz,table.hz tbody,table.hz tr,table.hz td{display:block;width:100%;box-sizing:border-box}
 table.hz tr{margin-bottom:16px;border:2px solid rgba(128,128,128,.45);border-radius:12px;overflow:hidden}
 table.hz td{border:0;border-bottom:1px solid rgba(128,128,128,.3)}
 table.hz td:last-child{border-bottom:0}
 table.hz td::before{content:attr(data-label);display:block;font-weight:700;font-size:.78rem;opacity:.7;margin-bottom:3px}
}
</style>
"""


def get_secret(name: str, default: str = "") -> str:
    try:
        v = st.secrets[name]
        if v:
            return str(v)
    except Exception:
        pass
    return os.getenv(name, default)


def fmt_date(s: str) -> str:
    return f"{s[:4]}-{s[4:6]}-{s[6:8]}" if re.fullmatch(r"\d{8}", s or "") else (s or "-")


def get_oc() -> str:
    return st.session_state.get("law_oc") or get_secret("LAW_OC")


def law_notice(kb: dict):
    """법령이 개정됐는지 하루 몇 번만 확인해 배너로 알립니다."""
    oc = get_oc()
    if not oc:
        return
    latest = cached_law_latest(oc)
    if "error" in latest:
        return
    m = kb["meta"]
    if not m["law_effective_date"]:
        st.info("법령 동기화를 아직 하지 않았습니다. 「🔄 기준 업데이트」 탭에서 한 번 실행해 주세요.")
    elif latest["effective"] != m["law_effective_date"] or latest["no"] != m["law_promulgation_no"]:
        st.warning(f"⚠ 산업안전보건기준에 관한 규칙이 개정된 것으로 보입니다 "
                   f"(현행 시행일 {fmt_date(latest['effective'])}, 기준 데이터 {fmt_date(m['law_effective_date'])}). "
                   "「🔄 기준 업데이트」 탭에서 동기화하세요.")


# ═════════════════════════════════════════════════════════════════════
# 8. 메인 탭 : 사진 → 판독 → 결과
# ═════════════════════════════════════════════════════════════════════
def render_result(res: dict, kb: dict):
    hz = res["hazards"]
    st.image(res["annotated"], caption="판독 결과 · 번호는 아래 표와 같습니다 (박스 위치는 AI 추정이라 오차가 있을 수 있음)")
    if res.get("scene"):
        st.markdown(f'<div class="note"><b>상황 요약</b> {esc(res["scene"])}</div>', unsafe_allow_html=True)
    if res.get("issues"):
        st.warning("사진 상태: " + " / ".join(res["issues"]))
    if not hz:
        st.success("이 사진에서는 뚜렷한 위험요인이 확인되지 않았습니다. 사진에 보이지 않는 부분은 현장에서 직접 점검하세요.")
    else:
        chips = "".join(f'<span class="chip" style="background:{SEV_COLOR[s]}">{s} {sum(1 for h in hz if h["severity"] == s)}건</span>'
                        for s in SEV_COLOR if any(h["severity"] == s for h in hz))
        st.markdown(f'<div class="sum">{chips}</div>', unsafe_allow_html=True)
        rows = build_rows(hz, kb)
        st.markdown(rows_to_html(rows), unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        c1.download_button("🖼 표시된 사진 저장", res["annotated"], file_name="hazard_marked.jpg", mime="image/jpeg")
        c2.download_button("📄 결과표 CSV 저장", rows_to_df(rows, kb).to_csv(index=False).encode("utf-8-sig"),
                           file_name="hazard_report.csv", mime="text/csv")
    if res.get("not_assessable"):
        with st.expander("사진만으로 판단하기 어려운 항목"):
            for t in res["not_assessable"]:
                st.write("• " + str(t))
    st.caption(f"기준 데이터 {kb['meta']['kb_version']} · 산안칙 시행일 {fmt_date(kb['meta']['law_effective_date'])} · "
               "AI 판독은 참고용입니다. 최종 판단은 안전관리자가 "
               f"[현행 법령 원문]({LAW_PAGE})과 KOSHA GUIDE 최신본으로 확인하세요.")


def render_main(kb: dict):
    key_ok = bool(st.session_state.get("api_key_input") or get_secret("OPENAI_API_KEY"))
    with st.expander("⚙️ 설정" + ("" if key_ok else "  ← API 키를 입력하세요"), expanded=not key_ok):
        st.text_input("OpenAI API 키", type="password", key="api_key_input", placeholder="sk-...",
                      help="이 브라우저 세션에만 저장됩니다. secrets.toml이나 환경변수로 미리 설정할 수도 있습니다.")
        st.text_input("모델", value="gpt-4o", key="model_name")
        st.caption("사진은 분석을 위해 OpenAI 서버로 전송됩니다. 얼굴·개인정보가 크게 찍히지 않도록 주의하세요.")
    law_notice(kb)

    mode = st.radio("사진 가져오기", ["📷 카메라로 촬영", "🖼️ 갤러리에서 선택"], horizontal=True,
                    label_visibility="collapsed")
    if mode.startswith("📷"):
        cam = st.camera_input("현장 사진 촬영", label_visibility="collapsed")
        raw = cam.getvalue() if cam else None
        st.caption("카메라가 전면으로 열리거나 화질이 아쉬우면 '갤러리에서 선택' → '사진 찍기'를 이용하세요. "
                   "(카메라 촬영은 HTTPS 주소에서만 동작합니다)")
    else:
        up = st.file_uploader("사진 선택", type=["jpg", "jpeg", "png", "webp"], label_visibility="collapsed")
        raw = up.getvalue() if up else None

    memo = st.text_input("작업 내용 메모 (선택)", placeholder="예: 3층 외벽 도장, 이동식비계 사용 중", max_chars=120)
    go = st.button("🔍 위험요인 판독하기", type="primary", disabled=raw is None)

    cur_hash = hashlib.md5(raw).hexdigest() if raw else None
    res = st.session_state.get("result")
    if res and res["hash"] != cur_hash:           # 다른 사진으로 바뀌면 이전 결과 숨김
        res = None
        st.session_state.pop("result", None)

    if go and raw:
        api_key = st.session_state.get("api_key_input") or get_secret("OPENAI_API_KEY")
        if not api_key:
            st.error("OpenAI API 키가 없습니다. 위 '설정'에 입력해 주세요.")
        else:
            try:
                with st.spinner("AI가 사진을 판독하는 중입니다… (10~30초)"):
                    img, jpg = prepare_image(raw)
                    result = analyze_image(api_key, st.session_state.get("model_name") or "gpt-4o", jpg, kb, memo)
                    hazards = normalize_hazards(result, kb)
                    res = {"hash": cur_hash, "hazards": hazards, "annotated": to_jpeg(annotate(img, hazards)),
                           "scene": str(result.get("scene_summary") or ""),
                           "issues": [str(x) for x in (result.get("image_issues") or [])],
                           "not_assessable": [str(x) for x in (result.get("not_assessable") or [])]}
                    st.session_state["result"] = res
            except openai.AuthenticationError:
                st.error("API 키가 올바르지 않습니다. 키를 다시 확인해 주세요.")
            except openai.RateLimitError:
                st.error("요청이 많거나 크레딧이 부족합니다. 잠시 후 다시 시도하거나 결제·한도를 확인하세요.")
            except openai.APIConnectionError:
                st.error("OpenAI 서버에 연결하지 못했습니다. 네트워크를 확인해 주세요.")
            except openai.BadRequestError as e:
                st.error(f"요청이 거절되었습니다(모델명·이미지 확인): {e}")
            except (json.JSONDecodeError, ValueError) as e:
                st.error(f"AI 응답을 해석하지 못했습니다. 다시 시도해 주세요. ({e})")
            except Exception as e:
                st.error(f"예상치 못한 오류: {e}")

    if res:
        render_result(res, kb)
    elif raw:
        st.image(raw, caption="선택한 사진 — 아래 버튼으로 판독을 시작하세요")


# ═════════════════════════════════════════════════════════════════════
# 9. 관리자 탭 : 법령·KOSHA GUIDE 업데이트
# ═════════════════════════════════════════════════════════════════════
def _s(x) -> str:
    return "" if x is None or (isinstance(x, float) and pd.isna(x)) else str(x).strip()


def _b(x) -> bool:
    return False if x is None or (isinstance(x, float) and pd.isna(x)) else bool(x)


def _split(x) -> list[str]:
    return [t.strip() for t in re.split(r"[;；\n]", _s(x)) if t.strip()]


def _flash(msg: str):
    st.session_state["flash"] = msg
    st.rerun()


def render_admin(kb: dict):
    pw = get_secret("ADMIN_PASSWORD")
    if pw:
        entered = st.text_input("관리자 비밀번호", type="password", key="adm_pw")
        if not hmac.compare_digest(entered.encode(), pw.encode()):
            st.info("관리자만 기준 데이터를 수정할 수 있습니다.")
            return
    else:
        st.warning("ADMIN_PASSWORD가 설정되지 않아 누구나 이 탭을 사용할 수 있습니다. 운영 시 비밀번호를 설정하세요.")
    if msg := st.session_state.pop("flash", None):
        st.success(msg)

    m, ver = kb["meta"], kb["meta"]["kb_version"]
    st.markdown("#### 현재 기준 데이터")
    st.write(f"**버전** {ver} · **저장** {m['updated_at']}")
    st.write(f"**산안칙 기준 시행일** {fmt_date(m['law_effective_date'])} (공포번호 {m['law_promulgation_no'] or '-'}) · "
             f"**마지막 법령 동기화** {m['law_synced_at'] or '없음'}")
    flagged = [r["article"] for r in kb["rules"] if r.get("state")]
    old_guides = [g["code"] for g in kb["guides"] if g["status"] != "현행"]
    st.write(f"조항 {len(kb['rules'])}개 · 지침 {len(kb['guides'])}개 · 위험요인 {len(kb['hazards'])}개")
    if flagged:
        st.warning("재검토 필요 조항: " + ", ".join(flagged))
    if old_guides:
        st.warning("상태 확인이 필요한 KOSHA GUIDE: " + ", ".join(old_guides))
    for w in check_refs(kb):
        st.error(w)
    st.caption(f"KOSHA GUIDE는 2026.1월 437건이 정비되며 번호 체계가 바뀌었습니다(예: D-C-7-2026). "
               f"[KOSHA 포털]({KOSHA_PORTAL})에서 최신본을 확인하세요.")

    # ── ① 법령 자동 동기화 ─────────────────────────────
    with st.expander("① 산안칙 자동 동기화 (국가법령정보센터 API)", expanded=False):
        st.caption("인증키(OC)는 open.law.go.kr 에서 무료 신청합니다. 동기화하면 등록된 조항의 제목·원문을 현행 법령과 대조해 "
                   "개정·삭제·이동된 조항을 표시합니다.")
        st.text_input("법령 API 인증키(OC)", type="password", key="law_oc", value=get_secret("LAW_OC"))
        if st.button("🔄 최신 법령과 동기화", key="btn_sync"):
            if not get_oc():
                st.error("인증키(OC)를 입력하세요.")
            else:
                try:
                    with st.spinner("법령 원문을 불러오는 중…"):
                        rep = sync_law(kb, get_oc())
                        save_kb(kb, "law_sync")
                        cached_law_latest.clear()
                    i = rep["info"]
                    lines = [f"시행 {fmt_date(i['effective'])} · 공포 {fmt_date(i['promulgation'])} · 공포번호 {i['no']} ({i['kind']})",
                             f"정상 {rep['ok']}건 · 조문 변경 {len(rep['changed'])}건 · 제목 불일치 {len(rep['title_mismatch'])}건 · "
                             f"미발견 {len(rep['missing'])}건 · 자동대조 제외 {len(rep['skipped'])}건"]
                    if rep["changed"]:
                        lines.append("조문 변경: " + ", ".join(rep["changed"]))
                    lines += [f"제목 불일치 {a}: 등록 '{o}' ↔ 현행 '{n}'" for a, o, n in rep["title_mismatch"]]
                    if rep["missing"]:
                        lines.append("미발견(삭제·이동 가능): " + ", ".join(rep["missing"]))
                    _flash("동기화 완료\n\n" + "\n\n".join(lines))
                except Exception as e:
                    st.error(f"동기화 실패: {e}")

    # ── ② 표 편집 ─────────────────────────────────────
    with st.expander("② 표에서 직접 수정 (PC 권장)", expanded=False):
        t_rules, t_guides, t_haz = st.tabs(["산안칙 조항", "KOSHA GUIDE", "위험요인 카탈로그"])
        with t_rules:
            df = pd.DataFrame([{k: r.get(k, "") for k in ("article", "title", "summary", "verified", "state")}
                               for r in kb["rules"]])
            ed = st.data_editor(df, num_rows="dynamic", key=f"ed_rules_{ver}", column_config={
                "article": "조항", "title": "제목", "summary": "요지", "verified": "검증", "state": "재검토 표시(지우면 해제)"})
            if st.button("조항 저장", key="sv_rules"):
                old = {r["article"]: r for r in kb["rules"]}
                new = []
                for _, row in ed.iterrows():
                    a = _s(row["article"])
                    if a:
                        new.append({**old.get(a, {}), "article": a, "title": _s(row["title"]), "summary": _s(row["summary"]),
                                    "verified": _b(row["verified"]), "state": _s(row["state"])})
                kb["rules"] = new
                save_kb(kb, "edit_rules")
                _flash("조항을 저장했습니다.")
        with t_guides:
            st.caption("지침이 개정·통합되어 번호가 바뀌면 구번호 행의 '대체 번호'에 신번호를 적으세요. 결과표에 신번호로 자동 연결됩니다.")
            df = pd.DataFrame([{k: g.get(k, "") for k in ("code", "title", "status", "superseded_by", "url", "note")}
                               for g in kb["guides"]])
            ed = st.data_editor(df, num_rows="dynamic", key=f"ed_guides_{ver}", column_config={
                "code": "코드", "title": "제목",
                "status": st.column_config.SelectboxColumn("상태", options=["현행", "확인필요", "폐지"]),
                "superseded_by": "대체 번호", "url": "링크", "note": "비고"})
            if st.button("지침 저장", key="sv_guides"):
                new = []
                for _, row in ed.iterrows():
                    c = _s(row["code"])
                    if c:
                        new.append({"code": c, "title": _s(row["title"]), "status": _s(row["status"]) or "확인필요",
                                    "superseded_by": _s(row["superseded_by"]), "url": _s(row["url"]), "note": _s(row["note"])})
                kb["guides"] = new
                save_kb(kb, "edit_guides")
                _flash("지침을 저장했습니다.")
        with t_haz:
            st.caption("여러 값은 세미콜론(;)으로 구분합니다. 조항·지침은 앞의 표에 있는 값을 그대로 적으세요.")
            df = pd.DataFrame([{"id": h["id"], "name": h["name"], "severity": h["severity"],
                                "keywords": "; ".join(h["keywords"]), "rules": "; ".join(h["rules"]),
                                "guides": "; ".join(h["guides"]), "actions": "; ".join(h["actions"])} for h in kb["hazards"]])
            ed = st.data_editor(df, num_rows="dynamic", key=f"ed_haz_{ver}", column_config={
                "id": "ID", "name": "위험요인",
                "severity": st.column_config.SelectboxColumn("기본 심각도", options=list(SEV_COLOR)),
                "keywords": "키워드(AI 매칭용)", "rules": "관련 조항", "guides": "관련 지침", "actions": "즉시 조치"})
            if st.button("위험요인 저장", key="sv_haz"):
                kb["hazards"] = [{"id": _s(r["id"]), "name": _s(r["name"]), "severity": _s(r["severity"]) or "중간",
                                  "keywords": _split(r["keywords"]), "rules": _split(r["rules"]),
                                  "guides": _split(r["guides"]), "actions": _split(r["actions"])}
                                 for _, r in ed.iterrows() if _s(r["id"])]
                save_kb(kb, "edit_hazards")
                _flash("위험요인을 저장했습니다.")

    # ── ③ 파일로 가져오기·내보내기 ───────────────────────
    with st.expander("③ 파일로 가져오기 · 내보내기", expanded=False):
        st.download_button("⬇ 기준 데이터 내려받기 (JSON)", json.dumps(kb, ensure_ascii=False, indent=2).encode("utf-8"),
                           file_name=f"safety_kb_{ver}.json", mime="application/json")
        st.markdown("**KOSHA GUIDE 목록 CSV 업로드** — 열: `code, title` (선택: `status, superseded_by, url, note`)")
        csv_up = st.file_uploader("CSV 파일", type=["csv"], key="csv_up")
        if csv_up and st.button("CSV로 지침 갱신(없으면 추가·있으면 덮어쓰기)", key="btn_csv"):
            data = csv_up.getvalue()
            text = None
            for enc in ("utf-8-sig", "cp949"):
                try:
                    text = data.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if text is None:
                st.error("CSV 인코딩을 읽을 수 없습니다. UTF-8 또는 CP949로 저장하세요.")
            else:
                alias = {"코드": "code", "지침번호": "code", "번호": "code", "제목": "title", "명칭": "title",
                         "상태": "status", "대체": "superseded_by", "대체번호": "superseded_by", "링크": "url", "비고": "note"}
                d = pd.read_csv(io.StringIO(text), dtype=str).fillna("")
                d = d.rename(columns={c: alias.get(c.strip(), c.strip()) for c in d.columns})
                if "code" not in d.columns:
                    st.error("'code'(또는 '코드') 열이 필요합니다.")
                else:
                    idx = {g["code"]: g for g in kb["guides"]}
                    for _, row in d.iterrows():
                        c = _s(row["code"])
                        if c:
                            base = idx.get(c, {"code": c, "title": "", "status": "현행", "superseded_by": "", "url": "", "note": ""})
                            for k in ("title", "status", "superseded_by", "url", "note"):
                                if k in d.columns and _s(row[k]):
                                    base[k] = _s(row[k])
                            idx[c] = base
                    kb["guides"] = list(idx.values())
                    save_kb(normalize_kb(kb), "csv_guides")
                    _flash(f"CSV {len(d)}행을 반영했습니다.")
        st.markdown("**기준 데이터 JSON 업로드**")
        mode = st.radio("반영 방식", ["병합(같은 키만 덮어쓰기)", "전체 교체"], horizontal=True, key="json_mode")
        j_up = st.file_uploader("JSON 파일", type=["json"], key="json_up")
        if j_up and st.button("JSON 반영", key="btn_json"):
            try:
                new = json.loads(j_up.getvalue().decode("utf-8-sig"))
                err = validate_kb(new)
                if err:
                    st.error(err)
                else:
                    out = normalize_kb(new) if mode == "전체 교체" else merge_kb(kb, new)
                    save_kb(out, "json_import")
                    _flash("JSON을 반영했습니다. (이전 상태는 자동 백업됨)")
            except Exception as e:
                st.error(f"JSON을 읽지 못했습니다: {e}")

    # ── ④ 백업 · 복원 · 이력 ─────────────────────────────
    with st.expander("④ 백업 · 복원 · 변경 이력", expanded=False):
        backups = sorted(BACKUP_DIR.glob("safety_kb_*.json"), reverse=True)
        if backups:
            pick = st.selectbox("복원할 백업", [b.name for b in backups], key="bk_pick")
            if st.button("이 백업으로 복원", key="btn_restore"):
                try:
                    data = json.loads((BACKUP_DIR / pick).read_text(encoding="utf-8"))
                    if validate_kb(data):
                        st.error("백업 파일이 올바르지 않습니다.")
                    else:
                        save_kb(normalize_kb(data), f"restore:{pick}")
                        _flash(f"{pick} 으로 복원했습니다.")
                except Exception as e:
                    st.error(f"복원 실패: {e}")
        else:
            st.caption("아직 백업이 없습니다. 기준 데이터를 저장하면 자동으로 생깁니다.")
        if LOG_PATH.exists():
            lines = LOG_PATH.read_text(encoding="utf-8").strip().splitlines()[-12:]
            st.caption("최근 변경 이력")
            for ln in reversed(lines):
                try:
                    j = json.loads(ln)
                    st.write(f"`{j['ts']}` {j['action']} — {j.get('detail', '')}")
                except Exception:
                    pass


# ═════════════════════════════════════════════════════════════════════
# 10. 앱 시작
# ═════════════════════════════════════════════════════════════════════
def main():
    st.set_page_config(page_title="현장 안전 판독", page_icon="🦺", layout="centered",
                       initial_sidebar_state="collapsed")
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown('<div class="hdr"><div class="stripe"></div><div class="ttl">현장 안전 판독</div>'
                '<p class="sub">사진 한 장으로 위험요인 · 위반 소지 조항 · 즉시 조치를 확인합니다</p></div>',
                unsafe_allow_html=True)
    kb = load_kb()
    tab_main, tab_admin = st.tabs(["🦺 사진 판독", "🔄 기준 업데이트"])
    with tab_main:
        render_main(kb)
    with tab_admin:
        render_admin(kb)


if __name__ == "__main__":
    main()
