# -*- coding: utf-8 -*-
# @Time : 2023/10/25 16:39
# @Author : ltm
# @Email :
# @Desc :https://github.com/dongrixinyu/JioNLP/blob/3c0c2558ea91a4e39743d80e778b3f65db9304cb/jionlp/rule/extractor.py

from presidio_analyzer import PatternRecognizer, Pattern, RecognizerResult, EntityRecognizer
import regex as re
from typing import List, Optional
from datetime import datetime  # 正确导入strptime所需的类
import logging

from presidio_analyzer.nlp_engine import NlpArtifacts
logger = logging.getLogger("presidio-analyzer-patch")


class PatchPatternRecognizer(PatternRecognizer):
    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: NlpArtifacts = None,
        regex_flags: int = None,
    ) -> List[RecognizerResult]:
        """
        Analyzes text to detect PII using regular expressions or deny-lists.

        :param text: Text to be analyzed
        :param entities: Entities this recognizer can detect
        :param nlp_artifacts: Output values from the NLP engine
        :param regex_flags:
        :return:
        """
        results = []
        if self.patterns:
            print('here')
            pattern_result = self._analyze_patterns(text, regex_flags)
            results.extend(pattern_result)

        return results

    def _analyze_patterns(
        self, text: str, flags: int = None
    ) -> List[RecognizerResult]:
        """
        Evaluate all patterns in the provided text.

        Including words in the provided deny-list

        :param text: text to analyze
        :param flags: regex flags
        :return: A list of RecognizerResult
        """
        flags = flags if flags else re.DOTALL | re.MULTILINE
        results = []
        text = ''.join(['#', text, '#'])
        for pattern in self.patterns:
            # 修复datetime调用方式
            match_start_time = datetime.now()  # 修改点1
            matches = re.finditer(pattern.regex, text, flags=flags)
            match_time = datetime.now() - match_start_time  # 修改点2
            logger.debug(
                "--- match_time[%s]: %s.%s seconds",
                pattern.name,
                match_time.seconds,
                match_time.microseconds,
            )

            for match in matches:
                start, end = match.span()
                current_match = text[start:end]

                # Skip empty results
                if current_match == "":
                    continue

                score = pattern.score

                validation_result = self.validate_result(current_match)
                description = self.build_regex_explanation(
                    self.name, pattern.name, pattern.regex, score, validation_result
                )
                pattern_result = RecognizerResult(
                    entity_type=self.supported_entities[0],
                    start=start-1,
                    end=end-1,
                    score=score,
                    analysis_explanation=description,
                    recognition_metadata={
                        RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                    },
                )

                if validation_result is not None:
                    if validation_result:
                        pattern_result.score = EntityRecognizer.MAX_SCORE
                    else:
                        pattern_result.score = EntityRecognizer.MIN_SCORE

                invalidation_result = self.invalidate_result(current_match)
                if invalidation_result is not None and invalidation_result:
                    pattern_result.score = EntityRecognizer.MIN_SCORE

                if pattern_result.score > EntityRecognizer.MIN_SCORE:
                    results.append(pattern_result)

                # Update analysis explanation score following validation or invalidation
                description.score = pattern_result.score

        results = EntityRecognizer.remove_duplicates(results)
        return results


class IDCardRecognizer(PatchPatternRecognizer):
    ID_CARD_PATTERN = r'(?<=[^0-9a-zA-Z])' \
                      r'((1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|81|82|91)' \
                      r'(0[0-9]|1[0-9]|2[0-9]|3[0-4]|4[0-3]|5[1-3]|90)' \
                      r'(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-3]|5[1-7]|6[1-4]|7[1-4]|8[1-7])' \
                      r'(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])' \
                      r'\d{3}[0-9xX])' \
                      r'(?=[^0-9a-zA-Z])'

    ID_CARD_CHECK_PATTERN = r'^(1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|81|82|91)' \
                            r'(0[0-9]|1[0-9]|2[0-9]|3[0-4]|4[0-3]|5[1-3]|90)' \
                            r'(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-3]|5[1-7]|6[1-4]|7[1-4]|8[1-7])' \
                            r'(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])\d{3}[0-9xX]$'

    PATTERNS = [
        Pattern(
            "IDCard",
            ID_CARD_PATTERN,
            0.5,
        ),
    ]

    CONTEXT = ["身份证号", "身份证"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "zh",
        supported_entity: str = "ID_CARD",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )
        self.id_card_check_pattern = re.compile(self.ID_CARD_CHECK_PATTERN)

    def invalidate_result(self, pattern_text: str) -> bool:
        """
        :param pattern_text: Text detected as pattern by regex
        :return: True if invalidated
        """
        match_flag = self.id_card_check_pattern.match(pattern_text)
        if match_flag is None:
            return True
        else:
            return False


# 新增以下几个自定义的Recognizer类
class BirthDateRecognizer(PatchPatternRecognizer):
    """识别出生日期"""
    BIRTH_DATE_PATTERN = r'(?<=(出生日期|出生年月|出生时间|生日)[:：\s]*)\d{4}[\.\-年]\d{1,2}[\.\-月]\d{1,2}日?'

    PATTERNS = [
        Pattern(
            "BIRTH_DATE",
            BIRTH_DATE_PATTERN,
            0.8,
        ),
    ]

    CONTEXT = ["出生日期", "出生年月", "出生时间", "生日"]

    def __init__(
      self,
      patterns: Optional[List[Pattern]] = None,
      context: Optional[List[str]] = None,
      supported_language: str = "zh",
      supported_entity: str = "BIRTH_DATE",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:
        """验证日期格式是否合法"""
        try:
            clean_date = (
                pattern_text
                .replace('年', '-').replace('月', '-').replace('日', '')
                .replace('..', '-').replace('.', '-')
            )
            # 统一格式为 YYYY-MM-DD
            parts = clean_date.split('-')
            if len(parts) == 3:
                year = parts[0].zfill(4)  # 确保4位数年份
                month = parts[1].zfill(2)  # 补零到2位数
                day = parts[2].zfill(2)    # 补零到2位数
                clean_date = f"{year}-{month}-{day}"
                datetime.strptime(clean_date, '%Y-%m-%d')  # 使用正确的函数
                return True
            return False
        except ValueError:
            return False


class HouseholdAddressRecognizer(PatchPatternRecognizer):
    """户籍地址识别器"""
    PATTERN = r'(?<=(户籍地址|户口所在地|户籍地)[:：\s]*)[^\n，。；！？]{5,40}'

    PATTERNS = [
        Pattern(
            "HOUSEHOLD_ADDRESS",
            PATTERN,
            0.8,
        ),
    ]

    CONTEXT = ["户籍地址", "户口所在地", "户籍地"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "zh",
        supported_entity: str = "HOUSEHOLD_ADDRESS",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return bool(re.search(r'(省|市|区|县|街道|路|号|村|乡|镇)', pattern_text))


class ResidentialAddressRecognizer(PatchPatternRecognizer):
    """居住地址识别器（增强版）"""
    # 增强模式：允许括号和空格，添加调试日志
    PATTERN = r'(?<=(居住地址|现住址|现居住地|住址)[:：\s]*\(?[\u4e00-\u9fa5a-zA-Z0-9]*\)?)[^\n，。；！？]{5,40}'

    PATTERNS = [
        Pattern(
            "RESIDENTIAL_ADDRESS",
            PATTERN,
            0.8,
        ),
    ]

    CONTEXT = ["居住地址", "现住址", "现居住地", "住址"]

    def __init__(
      self,
      patterns: Optional[List[Pattern]] = None,
      context: Optional[List[str]] = None,
      supported_language: str = "zh",
      supported_entity: str = "RESIDENTIAL_ADDRESS",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )
        # 添加调试日志
        logger.debug("初始化居住地址识别器 - 支持模式: %s", self.PATTERNS[0].regex)

    def validate_result(self, pattern_text: str) -> bool:
        """增强验证逻辑"""
        # 1. 检查地址特征词
        has_features = bool(re.search(r'(区|街道|路|号|院|楼|栋|单元|小区|社区|花园|新村|家园)', pattern_text))

        # 2. 检查地址格式（省市区结构）
        has_structure = bool(re.search(r'[省市区县].+[省市区县]', pattern_text))

        # 添加调试信息
        logger.debug("验证居住地址: %s | 特征: %s | 结构: %s",
                     pattern_text, has_features, has_structure)

        return has_features or has_structure

    def analyze(
      self,
      text: str,
      entities: List[str],
      nlp_artifacts: NlpArtifacts = None,
      regex_flags: int = None,
    ) -> List[RecognizerResult]:
        # 添加调试信息
        logger.debug("分析居住地址 - 文本: %s", text)
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)
        logger.debug("找到 %d 个居住地址匹配", len(results))
        return results


class MailingAddressRecognizer(PatchPatternRecognizer):
    """通讯地址识别器"""
    PATTERN = r'(?<=(通讯地址|联系地址|邮寄地址)[:：\s]*)[^\n，。；！？]{5,40}'

    PATTERNS = [
        Pattern(
            "MAILING_ADDRESS",
            PATTERN,
            0.8,
        ),
    ]

    CONTEXT = ["通讯地址", "联系地址", "邮寄地址"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "zh",
        supported_entity: str = "MAILING_ADDRESS",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return bool(re.search(r'(信箱|邮编|邮政|快递|收发室)', pattern_text))


class HomeAddressRecognizer(PatchPatternRecognizer):
    """家庭地址识别器（增强版）"""
    # 扩展模式：添加"家住"关键词，增强空格处理
    PATTERN = r'(?<=(家庭地址|家庭住址|住宅地址|家住|家在)[:：\s]*)[^\n，。；！？]{5,60}'

    PATTERNS = [
        Pattern(
            "HOME_ADDRESS",
            PATTERN,
            0.85,  # 提高置信度
        ),
    ]

    # 扩展上下文关键词
    CONTEXT = ["家庭地址", "家庭住址", "住宅地址", "家住", "家在"]

    def __init__(
      self,
      patterns: Optional[List[Pattern]] = None,
      context: Optional[List[str]] = None,
      supported_language: str = "zh",
      supported_entity: str = "HOME_ADDRESS",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )
        logger.debug(f"初始化家庭地址识别器（增强版），支持模式: {self.PATTERNS[0].regex}")

    def validate_result(self, pattern_text: str) -> bool:
        """增强家庭地址验证逻辑"""
        # 1. 检查地址特征词（扩展版）
        address_features = [
            "区", "街道", "路", "号", "院", "楼", "栋", "单元",
            "小区", "花园", "别墅", "新村", "家园", "大厦", "公寓"
        ]
        if any(feature in pattern_text for feature in address_features):
            return True

        # 2. 检查行政区划结构
        if re.search(r'(省|市|区|县|镇|乡|村).+', pattern_text):
            return True

        # 3. 检查地址格式（包含数字+单位）
        if re.search(r'\d+[号幢栋单元室层]', pattern_text):
            return True

        return False

    def analyze(
      self,
      text: str,
      entities: List[str],
      nlp_artifacts: NlpArtifacts = None,
      regex_flags: int = None,
    ) -> List[RecognizerResult]:
        """重写分析方法，增强家庭地址识别"""
        # 首先使用默认分析逻辑
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)

        # 额外尝试匹配"家住"开头的地址
        if not results:
            return self._find_home_address_after_jiazhu(text)

        return results

    def _find_home_address_after_jiazhu(self, text: str) -> List[RecognizerResult]:
        """查找'家住'后的家庭地址"""
        results = []
        # 查找"家住"后的地址
        jiazhu_pattern = r'(家住|家在)[:：\s]*([^\n，。；！？]{5,60})'
        matches = re.finditer(jiazhu_pattern, text)

        for match in matches:
            address_text = match.group(2)
            start, end = match.span(2)

            # 验证地址
            if not self.validate_result(address_text):
                continue

            # 创建结果对象
            description = self.build_regex_explanation(
                self.name, "HomeAfterJiazhu", jiazhu_pattern, self.PATTERNS[0].score, True
            )
            result = RecognizerResult(
                entity_type=self.supported_entities[0],
                start=start,
                end=end,
                score=self.PATTERNS[0].score,
                analysis_explanation=description,
                recognition_metadata={
                    RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                    RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                },
            )
            results.append(result)

        return results


class CompanyNameRecognizer(PatchPatternRecognizer):
    """公司名称识别器（增强后缀排除版）"""

    # 修改模式：添加后缀排除机制
    COMPANY_NAME_PATTERN = r'(?<=(甲方|乙方|公司名称|单位名称|企业名称|机构名称|所属单位|归|所属公司)[:：\s为]*)([^:\n，。；！？]{4,60}?)(?=(所有|保留|享有|拥有|归|的)?[\s\n。，；！？]|$)'

    PATTERNS = [
        Pattern(
            "COMPANY_NAME",
            COMPANY_NAME_PATTERN,
            0.85,
        ),
    ]

    # 保留原有上下文关键词
    CONTEXT = ["甲方", "乙方", "公司名称", "单位名称", "企业名称", "机构名称", "单位", "企业", "所属单位", "归", "所属公司"]

    # 保留原有公司后缀
    COMPANY_SUFFIXES = ["公司", "有限公司", "股份公司", "集团", "分公司", "厂", "所", "中心", "事务所", "工作室", "分行", "支行", "分店"]

    # 新增：个人字段排除词库
    PERSONAL_KEYWORD_BLACKLIST = {
        "姓名", "性别", "出生日期", "身份证号", "身份证", "户口", "户籍",
        "住址", "地址", "电话", "手机", "号码", "邮箱", "电子邮箱", "邮件",
        "民族", "婚姻", "政治面貌", "健康", "履历", "家庭", "成员", "关系"
    }

    # 新增：公司关键词白名单（增强验证）
    COMPANY_KEYWORD_WHITELIST = {
        "公司", "集团", "有限", "股份", "企业", "机构", "科技", "技术",
        "服务", "咨询", "国际", "银行", "保险", "证券", "事务所", "分行"
    }

    # 新增：需要排除的后缀词
    EXCLUDE_SUFFIXES = {"所有", "保留", "享有", "拥有", "归", "的"}

    def __init__(
      self,
      patterns: Optional[List[Pattern]] = None,
      context: Optional[List[str]] = None,
      supported_language: str = "zh",
      supported_entity: str = "COMPANY_NAME",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )
        logger.debug(f"初始化公司名称识别器（增强后缀排除版）")

    def validate_result(self, pattern_text: str) -> bool:
        """增强验证逻辑：添加后缀排除机制"""
        logger.debug(f"验证公司名称: {pattern_text}")

        # 1. 检查是否包含个人敏感词（黑名单）
        if any(keyword in pattern_text for keyword in self.PERSONAL_KEYWORD_BLACKLIST):
            logger.debug(f"排除包含个人敏感词: {pattern_text}")
            return False

        # 2. 检查是否包含公司后缀或白名单关键词
        has_suffix = any(suffix in pattern_text for suffix in self.COMPANY_SUFFIXES)
        has_company_keyword = any(keyword in pattern_text for keyword in self.COMPANY_KEYWORD_WHITELIST)

        if not (has_suffix or has_company_keyword):
            logger.debug(f"不包含公司特征词: {pattern_text}")
            return False

        # 3. 检查是否以排除后缀结尾
        if any(pattern_text.endswith(suffix) for suffix in self.EXCLUDE_SUFFIXES):
            logger.debug(f"以排除后缀结尾: {pattern_text}")
            return False

        # 4. 保留原有长度和格式检查
        valid_length_format = len(pattern_text) >= 4 and not re.fullmatch(r'\d+', pattern_text)

        return valid_length_format

    def _analyze_patterns(
      self, text: str, flags: int = None
    ) -> List[RecognizerResult]:
        """重写分析逻辑，准确提取公司名称"""
        flags = flags if flags else re.DOTALL | re.MULTILINE
        results = []
        text = ''.join(['#', text, '#'])  # 添加边界符

        for pattern in self.patterns:
            matches = re.finditer(pattern.regex, text, flags=flags)

            for match in matches:
                # 获取匹配的公司名称部分（第二个捕获组）
                company_text = match.group(2)
                start = match.start(2)
                end = match.end(2)

                # 跳过空匹配
                if not company_text:
                    continue

                # 新增：预过滤检查上下文
                preceding_text = text[max(0, start - 20):start]
                if any(keyword in preceding_text for keyword in self.PERSONAL_KEYWORD_BLACKLIST):
                    logger.debug(f"跳过个人敏感词附近匹配: {company_text}")
                    continue

                # 验证公司名称
                validation_result = self.validate_result(company_text)
                if not validation_result:
                    logger.debug(f"验证失败: {company_text}")
                    continue

                # 创建结果对象
                description = self.build_regex_explanation(
                    self.name, pattern.name, pattern.regex, pattern.score, validation_result
                )
                pattern_result = RecognizerResult(
                    entity_type=self.supported_entities[0],
                    start=start - 1,  # 减去边界符
                    end=end - 1,  # 减去边界符
                    score=pattern.score,
                    analysis_explanation=description,
                    recognition_metadata={
                        RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                    },
                )

                if pattern_result.score > EntityRecognizer.MIN_SCORE:
                    results.append(pattern_result)

        return EntityRecognizer.remove_duplicates(results)


class CompanyAddressRecognizer(PatchPatternRecognizer):
    """公司住所识别器（增强空格处理）"""
    COMPANY_ADDRESS_PATTERN = r'(?<=(住所|住\s*所|办公地址|公司所在地|公司地址|地址|注册地址)[:：\s]*)[^\n，。；！？]{5,60}'

    PATTERNS = [
        Pattern(
            "COMPANY_ADDRESS",
            COMPANY_ADDRESS_PATTERN,
            0.85,
        ),
    ]

    CONTEXT = ["住所", "住 所", "办公地址", "公司所在地", "公司地址", "地址", "注册地址"]

    def __init__(
      self,
      patterns: Optional[List[Pattern]] = None,
      context: Optional[List[str]] = None,
      supported_language: str = "zh",
      supported_entity: str = "COMPANY_ADDRESS",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )
        logger.debug(f"初始化公司住所识别器，支持模式: {self.PATTERNS[0].regex}")

    def validate_result(self, pattern_text: str) -> bool:
        """增强公司地址验证逻辑"""
        logger.debug(f"验证公司地址: {pattern_text}")

        # 1. 检查地址特征词（加强版）
        address_features = ["区", "街道", "路", "号", "院", "楼", "栋", "室", "大厦", "层"]
        if any(feature in pattern_text for feature in address_features):
            return True

        # 2. 检查行政区划结构（加强版）
        if re.search(r'(省|市|区|县|镇|乡|村).+(省|市|区|县|镇|乡|村)', pattern_text):
            return True

        # 3. 检查公司场所特征词（加强版）
        company_location_words = ["产业园", "科技园", "工业区", "商务区", "写字楼", "办公室", "基地", "园区"]
        if any(word in pattern_text for word in company_location_words):
            return True

        # 4. 检查地址格式（包含数字+单位）
        if re.search(r'\d+[号幢栋单元室层]', pattern_text):
            return True

        return False


class SalaryAmountRecognizer(PatternRecognizer):
    """工资金额识别器（完整版）"""

    # 匹配模式：灵活匹配各种工资表述
    SALARY_PATTERN = r'(?<=(工资|月工资|薪酬标准|月薪|年薪|薪资|报酬|薪金|收入|待遇)[:：\s为]*)' \
                     r'(税前|税后)?\s*' \
                     r'(人民币|RMB|￥|CNY)?\s*' \
                     r'([\d,]+(\.\d{1,2})?|[零壹贰叁肆伍陆柒捌玖拾佰仟万亿整]+)' \
                     r'\s*(元|人民币|RMB)?'

    PATTERNS = [
        Pattern(
            "SALARY_AMOUNT",
            SALARY_PATTERN,
            0.85,
        ),
    ]

    # 扩展上下文关键词
    CONTEXT = ["工资", "月工资", "薪酬标准", "月薪", "年薪", "薪资", "报酬", "薪金", "收入", "待遇"]

    # 中文大写数字映射
    CHINESE_NUMERALS = {
        '零': 0, '一': 1, '二': 2, '三': 3, '四': 4, '五': 5,
        '六': 6, '七': 7, '八': 8, '九': 9, '十': 10, '百': 100,
        '千': 1000, '万': 10000, '亿': 100000000, '整': 0
    }

    def __init__(
      self,
      patterns: Optional[List[Pattern]] = None,
      context: Optional[List[str]] = None,
      supported_language: str = "zh",
      supported_entity: str = "SALARY_AMOUNT",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )
        logger.debug(f"初始化工资金额识别器，支持模式: {self.PATTERNS[0].regex}")

    def validate_result(self, pattern_text: str) -> bool:
        """验证金额格式是否合理"""
        # 1. 检查是否包含数字或中文大写数字
        if not re.search(r'[\d零壹贰叁肆伍陆柒捌玖拾佰仟万亿]', pattern_text):
            return False

        # 2. 尝试解析金额
        try:
            amount = self.parse_amount(pattern_text)
            # 设置合理的工资范围（1000元 - 1000万元）
            return 1000 <= amount <= 10000000
        except (ValueError, TypeError):
            return False
        except Exception as e:
            logger.error(f"金额解析错误: {pattern_text} - {str(e)}")
            return False

    def analyze(
      self,
      text: str,
      entities: List[str],
      nlp_artifacts: NlpArtifacts = None,
      regex_flags: int = None,
    ) -> List[RecognizerResult]:
        """重写分析方法，增强工资金额识别"""
        # 首先使用默认分析逻辑
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)

        # 额外尝试匹配纯数字金额（针对"薪酬标准：36000"格式）
        if not results and "薪酬标准" in text:
            return self._find_standalone_amounts(text)

        return results

    def _find_standalone_amounts(self, text: str) -> List[RecognizerResult]:
        """查找独立数字金额"""
        results = []
        # 查找关键词后的数字金额
        standalone_pattern = r'(?<=(薪酬标准|工资|月薪)[:：\s为]+)([\d,]+(\.\d{1,2})?)'
        matches = re.finditer(standalone_pattern, text)

        for match in matches:
            amount_text = match.group(2)
            start, end = match.span(2)

            # 验证金额
            try:
                amount = self.parse_amount(amount_text)
                if not (1000 <= amount <= 10000000):
                    continue
            except Exception:
                continue

            # 创建结果对象
            description = self.build_regex_explanation(
                self.name, "StandaloneSalary", standalone_pattern, self.PATTERNS[0].score, True
            )
            result = RecognizerResult(
                entity_type=self.supported_entities[0],
                start=start,
                end=end,
                score=self.PATTERNS[0].score,
                analysis_explanation=description,
                recognition_metadata={
                    RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                    RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                    "amount": amount
                },
            )
            results.append(result)

        return results

    def parse_amount(self, text: str) -> float:
        """解析金额文本为数值"""
        # 清理文本：移除货币单位和空格
        clean_text = re.sub(r'(税前|税后|人民币|RMB|￥|CNY|元)', '', text).replace(',', '').strip()

        # 1. 处理数字金额
        if re.match(r'^[\d.]+$', clean_text):
            return float(clean_text)

        # 2. 处理中文大写金额
        return self.parse_chinese_amount(clean_text)

    def parse_chinese_amount(self, text: str) -> float:
        """解析中文大写金额为数值"""
        total = 0
        current = 0
        last_unit = 1

        # 处理特殊情况："整"表示整数
        if text.endswith('整'):
            text = text[:-1]

        # 逐个字符处理
        for char in text:
            if char in self.CHINESE_NUMERALS:
                value = self.CHINESE_NUMERALS[char]

                # 处理单位（十、百、千、万、亿）
                if value >= 10:
                    # 如果当前有数值，乘以单位
                    if current == 0:
                        current = 1
                    current *= value

                    # 处理万和亿的特殊情况（需要累加到总数）
                    if value >= 10000:
                        total += current
                        current = 0
                        last_unit = value
                else:
                    current += value
            else:
                raise ValueError(f"无效的中文字符: {char}")

        # 累加剩余部分
        total += current

        # 处理单位不一致的情况（如"十万"应为100000）
        if last_unit >= 10000 and total < last_unit:
            total *= last_unit

        return total

    def _analyze_patterns(
      self, text: str, flags: int = None
    ) -> List[RecognizerResult]:
        """重写分析逻辑，准确提取金额部分"""
        flags = flags if flags else re.DOTALL | re.MULTILINE
        results = []
        text = ''.join(['#', text, '#'])  # 添加边界符

        for pattern in self.patterns:
            matches = re.finditer(pattern.regex, text, flags=flags)

            for match in matches:
                start, end = match.span()
                full_match = text[start:end]

                # 提取金额部分（正则表达式的第4组）
                amount_text = match.group(4)
                if not amount_text:
                    logger.debug(f"未找到金额部分: {full_match}")
                    continue

                # 验证金额
                try:
                    amount = self.parse_amount(amount_text)
                    if not (1000 <= amount <= 10000000):
                        logger.debug(f"金额超出范围: {amount_text} ({amount})")
                        continue
                except Exception as e:
                    logger.debug(f"金额解析失败: {amount_text} - {str(e)}")
                    continue

                # 计算金额部分的实际位置
                amount_start = start + match.start(4)
                amount_end = start + match.end(4)

                # 创建结果对象
                description = self.build_regex_explanation(
                    self.name, pattern.name, pattern.regex, pattern.score, True
                )
                result = RecognizerResult(
                    entity_type=self.supported_entities[0],
                    start=amount_start - 1,  # 减去边界符
                    end=amount_end - 1,  # 减去边界符
                    score=pattern.score,
                    analysis_explanation=description,
                    recognition_metadata={
                        RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                        "amount": amount,
                        "full_match": full_match
                    },
                )
                results.append(result)

        return EntityRecognizer.remove_duplicates(results)


class BankCardRecognizer(PatchPatternRecognizer):
    """银行卡号识别器（修复版）"""

    # 匹配模式：支持多种格式的银行卡号
    BANK_CARD_PATTERN = r'(?<=(银行卡|储蓄卡|信用卡|借记卡|工资卡|卡号|账号|账户)[:：\s]*)[0-9\s\-]{14,22}'

    # 中国主要银行的BIN号前缀（部分）
    BANK_BIN_PREFIXES = {
        # 中国银行
        "中国银行": ["6227", "4563", "6216", "6217", "6259"],
        # 工商银行
        "工商银行": ["6222", "6212", "6217", "6258", "6259"],
        # 建设银行
        "建设银行": ["6227", "6217", "6259", "4367", "5240"],
        # 农业银行
        "农业银行": ["6228", "6229", "6213", "6216", "6259"],
        # 交通银行
        "交通银行": ["6222", "6213", "6217", "6259", "4581"],
        # 招商银行
        "招商银行": ["6225", "6226", "6214", "6217", "6259"],
        # 邮政储蓄
        "邮政储蓄": ["6221", "6210", "6217", "6259", "6222"],
        # 民生银行
        "民生银行": ["6226", "4213", "6217", "6259", "6222"],
        # 光大银行
        "光大银行": ["6226", "6227", "6217", "6259", "6222"],
        # 中信银行
        "中信银行": ["6226", "6227", "6217", "6259", "6222"],
        # 平安银行
        "平安银行": ["6221", "6222", "6217", "6259", "6222"],
        # 浦发银行
        "浦发银行": ["6225", "6226", "6217", "6259", "6222"],
        # 广发银行
        "广发银行": ["6225", "6226", "6217", "6259", "6222"],
        # 华夏银行
        "华夏银行": ["6226", "6227", "6217", "6259", "6222"],
        # 兴业银行
        "兴业银行": ["6229", "6227", "6217", "6259", "6222"],
    }

    PATTERNS = [
        Pattern(
            "BANK_CARD",
            BANK_CARD_PATTERN,
            0.9,
        ),
    ]

    CONTEXT = ["银行卡", "储蓄卡", "信用卡", "借记卡", "工资卡", "卡号", "账号", "账户"]

    def __init__(
      self,
      patterns: Optional[List[Pattern]] = None,
      context: Optional[List[str]] = None,
      supported_language: str = "zh",
      supported_entity: str = "BANK_CARD",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )
        logger.debug(f"初始化银行卡号识别器，支持模式: {self.PATTERNS[0].regex}")

    def validate_result(self, pattern_text: str) -> bool:
        """验证银行卡号格式是否合法"""
        # 1. 清理文本：移除空格和连字符
        clean_text = re.sub(r'[\s\-]', '', pattern_text)

        # 2. 检查长度（中国银行卡号通常为16-19位）
        if not (16 <= len(clean_text) <= 19):
            logger.debug(f"银行卡号长度无效: {clean_text} ({len(clean_text)}位)")
            return False

        # 3. 检查是否为纯数字
        if not clean_text.isdigit():
            logger.debug(f"银行卡号包含非数字字符: {clean_text}")
            return False

        # 4. 检查BIN前缀（银行标识号）
        bin_valid = False
        matched_bank = None
        matched_prefix = None

        for bank, prefixes in self.BANK_BIN_PREFIXES.items():
            for prefix in prefixes:
                if clean_text.startswith(prefix):
                    bin_valid = True
                    matched_bank = bank
                    matched_prefix = prefix
                    logger.debug(f"匹配到{matched_bank}的BIN前缀: {matched_prefix}")
                    break
            if bin_valid:
                break

        # 5. Luhn算法验证（校验位检查）
        if not self.luhn_check(clean_text):
            logger.debug(f"银行卡号校验失败(Luhn算法): {clean_text}")
            return False

        return True

    def luhn_check(self, card_number: str) -> bool:
        """使用Luhn算法验证银行卡号"""
        total = 0
        reverse_digits = card_number[::-1]

        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:  # 从右向左，偶数位（索引从0开始）
                n *= 2
                if n > 9:
                    n = (n % 10) + 1  # 或者 n - 9
            total += n

        return total % 10 == 0

    def analyze(
      self,
      text: str,
      entities: List[str],
      nlp_artifacts: NlpArtifacts = None,
      regex_flags: int = None,
    ) -> List[RecognizerResult]:
        """重写分析方法，增强银行卡号识别"""
        # 首先使用默认分析逻辑
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)

        # 额外尝试匹配表格格式的银行卡号
        if not results:
            return self._find_table_format_cards(text)

        return results

    def _find_table_format_cards(self, text: str) -> List[RecognizerResult]:
        """查找表格格式的银行卡号"""
        results = []
        # 查找"工资卡卡号"后的银行卡号
        table_pattern = r'(工资卡卡号|银行卡号|卡号)[:：\s]*([0-9\s\-]{14,22})'
        matches = re.finditer(table_pattern, text)

        for match in matches:
            card_text = match.group(2)
            start, end = match.span(2)

            # 验证银行卡号
            if not self.validate_result(card_text):
                continue

            # 创建结果对象
            description = self.build_regex_explanation(
                self.name, "TableBankCard", table_pattern, self.PATTERNS[0].score, True
            )
            result = RecognizerResult(
                entity_type=self.supported_entities[0],
                start=start,
                end=end,
                score=self.PATTERNS[0].score,
                analysis_explanation=description,
                recognition_metadata={
                    RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                    RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                },
            )
            results.append(result)

        return results