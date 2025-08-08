# -*- coding: utf-8 -*-
# @Time : 2023/10/19 10:37
# @Author : ltm
# @Email :
# @Desc :

import dotenv
import os

if os.path.exists('../.env'):
    dotenv.load_dotenv('../.env')

from src.core.presido import pii_engine, AnalyzeResult, OperatorConf, CustomAnalyzeModel


if __name__ == '__main__':
    lang = 'zh'
    supported_entities = pii_engine.get_supported_entities(lang)
    print(supported_entities)

    text = '我叫李雷，性别男，家住北京市朝阳区光华路7号汉威大厦，我的身份证号码是411323198303155953，我的的电话号码是13122832932'
    # text = "Li Lei's phone number is 13122832932"
    result = pii_engine.analyze(text=text,
                                entities=["PHONE_NUMBER", "PERSON", "ID_CARD"],
                                language=lang,
                                score_threshold=0.3)
    print(result)

    supported_operaters = pii_engine.get_supported_anonymizers()
    print(supported_operaters)

    analyzer_results = [AnalyzeResult(entity_type="PERSON", start=2, end=4, score=0.85)]
    operators = [OperatorConf(entity_type="PERSON", operator_name="replace", params={"new_value": "[姓名]"})]
    result = pii_engine.anonymize(text, analyzer_results, False, operators)
    print(result)

    analyzer_results2 = [AnalyzeResult(entity_type="PHONE_NUMBER", start=62,end=73,score=0.75)]
    operators2 = [OperatorConf(entity_type="PHONE_NUMBER", operator_name="replace", params={"new_value": "[手机号码]"})]
    result2 = pii_engine.anonymize(text, analyzer_results2, False, operators2)
    print(result2)

    analyzer_results3 = [AnalyzeResult(entity_type="ID_CARD", start=35, end=53, score=0.85)]
    operators3 = [OperatorConf(entity_type="ID_CARD", operator_name="replace", params={"new_value": "[证件号码]"})]
    result3 = pii_engine.anonymize(text, analyzer_results3, False, operators3)
    print(result3)

    #
    # result = pii_engine.anonymize(text, analyzer_results, True, operators)
    # print(result)

    custom_entity = [CustomAnalyzeModel(entity='abc', deny_list=['电话', '是'])]
    result = pii_engine.custom_analyze("李雷的电话号码是13122832932", 'zh', custom_entity, [])
    print(result)
