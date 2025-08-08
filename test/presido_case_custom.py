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

    # text = '我叫李雷，性别男，家住北京市朝阳区光华路7号汉威大厦，电子邮箱为592290232@QQ.COM，我的身份证号码是411323198303155953，我的的电话号码是13122832932'
    # text = '乙方：姓 名 张大勇 性别 男 出生日期 1982.11.9\n身份证号 110226198211093312 户口所在地 北京市平谷区大兴庄镇韩屯大街113号\n现居住地址（有效通讯地址） 北京市大兴区新源大街25号院21号楼1404\n手机号码： 13520620405 电子邮箱 laterballen@163.com\n家庭地址： 北京市大兴区新源大街25号院21号楼1404\n家庭电话： /\n根据相关法律法规的规定，依据甲方的项目安排，经甲乙双方协商一致，双方同意通过电子签约方式\n签订本合同：'
    # text = '甲方：中智项目外包服务有限公司顺义分公司\n住 所：北京市顺义区格吉路1号院4号楼二层218室\n负责人：王安琪'
    # text = '乙方正常工作期间的月工资为税前人民币 36000 元，'
    # text = '薪酬标准：36000'
    # text = '五、手册制定及解释权\n5.1 手册解释权\n本手册的最终解释权归中智项目外包服务有限公司顺义分公司。本手册未做规定的，按《劳动合同法》\n的规定执行。如国家新颁布的法律法规与本手册的内容不一致的，以新颁布的法律法规为准。\n附件3\n服务信息登记表\n姓 名 张大勇 身份证号 110226198211093312\n出生日期 1982.11.9 性别 男 婚姻状态 已婚\n民族 汉族 政治面貌 群众\n生育情况 一胎（子） 健康状态 良好\n户口所在地 北京市平谷区大兴庄镇韩屯大街113号 户口性质 北京城镇\n计算机科学与技\n最高学历 大学本科 毕业院校 北京工业大学 毕业时间 2005.7 专业\n术\n家庭地址 北京市大兴区新源大街25号院21号楼1404\n家庭电话 13520620405 手机号码 13520620405 个人邮箱 laterballen@163.com\n工资卡开户行 工资卡开\n工资卡卡号 6217900100026373517 北京 中国银行北京黄寺支行\n城市 户行名称\n本人履历（从最高学历起填写）\n起止时间（年月） 单位 部门职务 证明人 证明人职位 证明人联系方式\n惠然科技有限公 S&E BU/软件工程 S&E应用软件部\n2023.1.4 - 2025.5.20\n司北京分公司 师 邵洪亮 部长 13911571945\n北京迈琪可兰科 软件部/部门负责\n2014.4 – 2022.12\n技有限公司 人 刘腾 总经理 18600207160\n北京圣世福昊达\n2005.7 – 2014.3 科技发展有限公 软件部/软件工程\n司 师 王浩 总经理 13911326060\n姓名 关系 出生日期 工作单位 联系电话\n主要\n张兰 夫妻 1983 北京京供民科技开发有限公司 13466682182\n家庭\n成员 / / / / /\n/ / / / /\n本人声明：\n1、此表注意事项已阅读，以上情况均如实、正确填写，如与事实不符，属于提供虚假个人资料，本人愿意接受解除劳动关系的处理结果。\n2、税务系统中，个税专项扣缴填报的信息准确、真实，本人已知出现虚假填报，属于严重违纪，公司可以以此解除劳动关系。"'
    # text = '五、手册制定及解释权\n5.1 手册解释权\n本手册的最终解释权归中智项目外包服务有限公司顺义分公司。本手册未做规定的，按《劳动合同法》\n的规定执行。如国家新颁布的法律法规与本手册的内容不一致的，以新颁布的法律法规为准。\n附件3\n服务信息登记表\n姓 名 张大勇 身份证号 110226198211093312\n出生日期 1982.11.9 性别 男 婚姻状态 已婚\n民族 汉族 政治面貌 群众\n生育情况 一胎（子） 健康状态 良好\n户口所在地 北京市平谷区大兴庄镇韩屯大街113号 户口性质 北京城镇\n计算机科学与技\n最高学历 大学本科 毕业院校 北京工业大学 毕业时间 2005.7 专业\n术\n家庭地址 北京市大兴区新源大街25号院21号楼1404\n家庭电话 13520620405 手机号码 13520620405 个人邮箱 laterballen@163.com\n工资卡开户行 工资卡开\n工资卡号 6217900100026373517 北京 中国银行北京黄寺支行\n城市 户行名称\n本人履历（从最高学历起填写）\n起止时间（年月） 单位 部门职务 证明人 证明人职位 证明人联系方式\n惠然科技有限公 S&E BU/软件工程 S&E应用软件部\n2023.1.4 - 2025.5.20\n司北京分公司 师 邵洪亮 部长 13911571945\n北京迈琪可兰科 软件部/部门负责\n2014.4 – 2022.12\n技有限公司 人 刘腾 总经理 18600207160\n北京圣世福昊达\n2005.7 – 2014.3 科技发展有限公 软件部/软件工程\n司 师 王浩 总经理 13911326060\n姓名 关系 出生日期 工作单位 联系电话\n主要\n张兰 夫妻 1983 北京京供民科技开发有限公司 13466682182\n家庭\n成员 / / / / /\n/ / / / /\n本人声明：\n1、此表注意事项已阅读，以上情况均如实、正确填写，如与事实不符，属于提供虚假个人资料，本人愿意接受解除劳动关系的处理结果。\n2、税务系统中，个税专项扣缴填报的信息准确、真实，本人已知出现虚假填报，属于严重违纪，公司可以以此解除劳动关系。"'
    # text = '五、手册制定及解释权\n5.1 手册解释权\n本手册的最终解释权归中智项目外包服务有限公司顺义分公司。'
    text = '五、手册制定及解释权\n5.1 手册解释权\n本手册的最终解释权归中智项目外包服务有限公司顺义分公司所有。'

    print('原始内容：' + text)
    # 动态实体处理方案
    entity_operator_mapping = {
        "PERSON": "[姓名]",
        "ID_CARD": "[证件号码]",
        "PHONE_NUMBER": "[手机号码]",
        "EMAIL_ADDRESS": "[电子邮箱]",
        # 新增以下自定义的Recognizer
        "BIRTH_DATE": "[出生日期]",
        "HOUSEHOLD_ADDRESS": "[户口所在地]",  # 户口所在地
        "RESIDENTIAL_ADDRESS": "[现居住地址]", # 现居住地址
        "MAILING_ADDRESS": "[通讯地址]",     # 通讯地址
        "HOME_ADDRESS": "[家庭地址]",        # 新增：家庭地址
        "COMPANY_NAME": "[公司名称]",
        "COMPANY_ADDRESS": "[公司地址]",
        "SALARY_AMOUNT": "[工资金额]",
        "BANK_CARD": "[银行卡号]",
    }

    # 步骤1：从映射字典直接获取实体列表，确保完全同步
    entities_to_process = list(entity_operator_mapping.keys())

    # 使用analyze方法一次性识别所有需要处理的实体
    analyze_results = pii_engine.analyze(
        text=text,
        entities=entities_to_process,  # 动态使用映射中的键
        language=lang,
        score_threshold=0.3
    )
    print(f"识别结果: {analyze_results}")

    # 步骤2：自动构建分析结果和操作配置
    analyzer_result_list = []
    operator_conf_list = []

    # 按起始位置降序排序（关键：解决替换时的位置偏移问题）
    sorted_results = sorted(analyze_results, key=lambda x: x['start'], reverse=True)

    for result in sorted_results:
        entity_type = result['entity_type']

        # 仅处理配置了映射的实体
        if entity_type in entity_operator_mapping:
            # 自动添加实体识别结果
            analyzer_result_list.append(
                AnalyzeResult(
                    entity_type=entity_type,
                    start=result['start'],
                    end=result['end'],
                    score=result['score']
                )
            )

            # 自动添加对应的操作配置
            operator_conf_list.append(
                OperatorConf(
                    entity_type=entity_type,
                    operator_name="replace",
                    params={"new_value": entity_operator_mapping[entity_type]}
                )
            )

    # 步骤3：单次调用完成所有脱敏操作
    final_result = pii_engine.anonymize(
        text=text,
        analyzer_results=analyzer_result_list,
        llm_synthesize=False,
        operators=operator_conf_list
    )

    print(f"最终脱敏结果: {final_result}")

    # （可选）获取完整支持的实体类型
    all_supported_entities = pii_engine.get_supported_entities(lang)
    print(f"系统支持的全部实体类型: {all_supported_entities}")
