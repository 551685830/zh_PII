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
    """家庭地址识别器"""
    PATTERN = r'(?<=(家庭地址|家庭住址|住宅地址)[:：\s]*)[^\n，。；！？]{5,40}'

    PATTERNS = [
        Pattern(
            "HOME_ADDRESS",
            PATTERN,
            0.8,
        ),
    ]

    CONTEXT = ["家庭地址", "家庭住址", "住宅地址"]

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

    def validate_result(self, pattern_text: str) -> bool:
        """验证家庭地址是否合理"""
        return bool(re.search(r'(区|街道|路|号|院|楼|栋|单元|小区|花园|别墅|新村|家园)', pattern_text))


class CompanyNameRecognizer(PatchPatternRecognizer):
    """公司名称识别器（增强版）"""

    # 增强匹配模式：支持"归XXX公司"等多种表达方式
    COMPANY_NAME_PATTERN = r'(?<=(甲方|乙方|公司名称|单位名称|企业名称|机构名称|所属单位|归|所属公司)[:：\s为]*)[^:\n，。；！？]{4,60}(?=[\s\n。])'

    PATTERNS = [
        Pattern(
            "COMPANY_NAME",
            COMPANY_NAME_PATTERN,
            0.85,
        ),
    ]

    # 扩展上下文关键词
    CONTEXT = ["甲方", "乙方", "公司名称", "单位名称", "企业名称", "机构名称", "单位", "企业", "所属单位", "归", "所属公司"]

    # 公司名称常见后缀（扩展版）
    COMPANY_SUFFIXES = ["公司", "有限公司", "股份公司", "集团", "分公司", "厂", "所", "中心", "事务所", "工作室", "分行", "支行", "分店"]

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
        logger.debug(f"初始化公司名称识别器，支持模式: {self.PATTERNS[0].regex}")

    def validate_result(self, pattern_text: str) -> bool:
        """增强公司名称验证"""
        logger.debug(f"验证公司名称: {pattern_text}")

        # 1. 检查是否包含公司常见后缀
        if any(suffix in pattern_text for suffix in self.COMPANY_SUFFIXES):
            return True

        # 2. 检查是否包含公司特征词
        company_keywords = ["企业", "机构", "集团", "事务所", "科技", "技术", "服务", "咨询", "国际", "银行", "保险", "证券"]
        if any(keyword in pattern_text for keyword in company_keywords):
            return True

        # 3. 检查长度和格式（排除纯数字）
        return len(pattern_text) >= 4 and not re.fullmatch(r'\d+', pattern_text)

    def _analyze_patterns(
      self, text: str, flags: int = None
    ) -> List[RecognizerResult]:
        """重写分析逻辑，增强公司名称识别"""
        flags = flags if flags else re.DOTALL | re.MULTILINE
        results = []
        text = ''.join(['#', text, '#'])  # 添加边界符

        for pattern in self.patterns:
            matches = re.finditer(pattern.regex, text, flags=flags)

            for match in matches:
                start, end = match.span()
                current_match = text[start:end]

                # 跳过空匹配
                if current_match == "":
                    continue

                # 验证公司名称
                validation_result = self.validate_result(current_match)
                if not validation_result:
                    logger.debug(f"验证失败: {current_match}")
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

    def analyze(
      self,
      text: str,
      entities: List[str],
      nlp_artifacts: NlpArtifacts = None,
      regex_flags: int = None,
    ) -> List[RecognizerResult]:
        """重写分析方法，增强公司名称识别"""
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)

        # 额外尝试匹配"归XXX公司"格式
        if not results:
            return self._find_company_after_gui(text)

        return results

    def _find_company_after_gui(self, text: str) -> List[RecognizerResult]:
        """查找'归'字后的公司名称"""
        results = []
        # 查找"归"字后的公司名称
        gui_pattern = r'(归|属于|隶属于)\s*([^。\n]{4,60}?)(公司|集团|厂|所|中心|事务所|分行|支行|分店)'
        matches = re.finditer(gui_pattern, text)

        for match in matches:
            company_text = match.group(2) + match.group(3)  # 组合公司名称
            start, end = match.span(2)  # 从公司名称部分开始

            # 验证公司名称
            if not self.validate_result(company_text):
                continue

            # 创建结果对象
            description = self.build_regex_explanation(
                self.name, "CompanyAfterGui", gui_pattern, self.PATTERNS[0].score, True
            )
            result = RecognizerResult(
                entity_type=self.supported_entities[0],
                start=start,
                end=end + len(match.group(3)),  # 包含后缀
                score=self.PATTERNS[0].score,
                analysis_explanation=description,
                recognition_metadata={
                    RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                    RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                },
            )
            results.append(result)

        return results


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