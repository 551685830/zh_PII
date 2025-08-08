# -*- coding: utf-8 -*-
# @Time : 2023/10/18 10:57
# @Author : ltm
# @Email :
# @Desc :
from typing import Optional

from loguru import logger
from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse

from .schema import AnonymizeModel, AnalyzeModel, AnalyzeResult, CustomAnalyze, FileAnalyzeModel, OperatorConf, Lang
from ..core.presido import pii_engine

import os

router = APIRouter()


def validate_open_key(llm_synthesize=False):
    if llm_synthesize and not os.getenv('OPENAI_API_KEY'):
        raise ValueError('OPENAI_API_KEY not configured, can not use llm_synthesize')


@router.get('/supported_entities/{language}')
def supported_entities(language: str):
    """Return a list of supported entities."""
    try:
        entities_list = pii_engine.get_supported_entities(language)
    except Exception as e:
        msg = f"get_supported_entities {language} catch error: {e}"
        logger.exception(msg)
        return JSONResponse(content={'status': 500, 'msg': msg, 'data': []})

    return JSONResponse(content={'status': 200, 'msg': 'success', 'data': entities_list})


@router.get('/supported_anonymizers')
def supported_anonymizers():
    try:
        operators = pii_engine.get_supported_anonymizers()
    except Exception as e:
        msg = f"get_supported_anonymizers error: {e}"
        logger.exception(msg)
        return JSONResponse(content={'status': 500, 'msg': msg, 'data': []})

    return JSONResponse(content={'status': 200, 'msg': 'success', 'data': operators})


@router.post('/anonymize')
def anonymize(item: AnonymizeModel):
    try:
        validate_open_key(item.llm_synthesize)
        result = pii_engine.anonymize(item.text, item.analyzer_results, item.llm_synthesize, item.operators)
    except Exception as e:
        msg = f"anonymize error: {e}"
        logger.exception(msg)
        return JSONResponse(content={'status': 500, 'msg': msg, 'data': []})

    return JSONResponse(content={'status': 200, 'msg': 'success', 'data': result})


@router.post('/analyze')
def analyze(item: AnalyzeModel):
    result = {"analyze": [], "anonymize": []}
    try:
        validate_open_key(item.llm_synthesize)
        result_analyze = pii_engine.analyze(item.text, item.lang, item.entities, item.score_threshold, item.allow_list)
        if item.with_anonymize:
            analyzer_results = [[AnalyzeResult(entity_type=r['entity_type'], start=r['start'], end=r['end'], score=r['score'])] for r in result_analyze]
            result_anonymize = pii_engine.anonymize(item.text, analyzer_results, item.llm_synthesize, item.anonymize_operators)
            result["anonymize"] = result_anonymize
        result["analyze"] = result_analyze
    except Exception as e:
        msg = f"analyze error: {e}"
        logger.exception(msg)
        return JSONResponse(content={'status': 500, 'msg': msg, 'data': result})

    return JSONResponse(content={'status': 200, 'msg': 'success', 'data': result})


@router.post('/custom_analyze')
def custom_analyze(item: CustomAnalyze):
    result = {"analyze": [], "anonymize": []}
    try:
        validate_open_key(item.llm_synthesize)
        result_analyze = pii_engine.custom_analyze(item.text, item.lang, item.entities, item.allow_list)
        if item.with_anonymize:
            analyzer_results = [[AnalyzeResult(entity_type=r['entity_type'], start=r['start'], end=r['end'], score=r['score'])] for r in result_analyze]
            result_anonymize = pii_engine.anonymize(item.text, analyzer_results, item.llm_synthesize, item.anonymize_operators)
            result["anonymize"] = result_anonymize
        result["analyze"] = result_analyze
    except Exception as e:
        msg = f"analyze error: {e}"
        logger.exception(msg)
        return JSONResponse(content={'status': 500, 'msg': msg, 'data': result})

    return JSONResponse(content={'status': 200, 'msg': 'success', 'data': result})


# 在 view.py 中添加以下路由实现

@router.post('/file_analyze')
def file_analyze(item: FileAnalyzeModel):
    """动态实体脱敏处理"""
    result = {"analyze": [], "anonymize": ""}

    try:
        # 验证 OpenAI API Key
        validate_open_key(item.llm_synthesize)

        # 从映射字典动态获取实体列表
        entities_to_process = list(item.entity_mapping.keys())

        # 执行分析
        result_analyze = pii_engine.analyze(
            text=item.text,
            language=item.lang.value,
            entities=entities_to_process,
            score_threshold=0.3,
            allow_list=item.allow_list
        )

        result["analyze"] = result_analyze

        # 如果需要脱敏处理
        if item.with_anonymize:
            # 构建分析结果对象列表
            analyzer_results = []
            for res in result_analyze:
                analyzer_results.append(
                    AnalyzeResult(
                        entity_type=res['entity_type'],
                        start=res['start'],
                        end=res['end'],
                        score=res['score']
                    )
                )

            # 构建操作符配置列表
            operators = item.anonymize_operators or []
            for entity_type, new_value in item.entity_mapping.items():
                # 如果未在自定义操作符中配置，添加默认替换操作
                if not any(op.entity_type == entity_type for op in (operators or [])):
                    operators.append(
                        OperatorConf(
                            entity_type=entity_type,
                            operator_name="replace",
                            params={"new_value": new_value}
                        )
                    )

            # 执行脱敏
            anonymize_result = pii_engine.anonymize(
                text=item.text,
                analyzer_results=analyzer_results,
                llm_synthesize=item.llm_synthesize,
                operators=operators
            )

            result["anonymize"] = anonymize_result

    except Exception as e:
        msg = f"文件脱敏处理错误: {e}"
        logger.exception(msg)
        return JSONResponse(content={'status': 500, 'msg': msg, 'data': result})

    return JSONResponse(content={'status': 200, 'msg': 'success', 'data': result})


@router.post('/file_upload_analyze')
async def file_upload_analyze(
  file: UploadFile = File(...),
  lang: Lang = Lang.zh,
  entity_mapping: str = '{"PERSON": "[姓名]"}',
  with_anonymize: bool = True,
  llm_synthesize: bool = False,
  allow_list: Optional[str] = None
):
    """文件上传脱敏处理"""
    try:
        # 读取文件内容
        content = (await file.read()).decode("utf-8")

        # 解析 JSON 配置
        import json
        mapping = json.loads(entity_mapping)
        allow_list_parsed = json.loads(allow_list) if allow_list else None

        # 构建请求模型
        request_data = FileAnalyzeModel(
            text=content,
            lang=lang,
            entity_mapping=mapping,
            with_anonymize=with_anonymize,
            llm_synthesize=llm_synthesize,
            allow_list=allow_list_parsed
        )

        # 调用处理函数
        return file_analyze(request_data)

    except json.JSONDecodeError:
        msg = "JSON 格式解析错误"
        logger.error(msg)
        return JSONResponse(content={'status': 400, 'msg': msg, 'data': {}})

    except Exception as e:
        msg = f"文件上传处理错误: {e}"
        logger.exception(msg)
        return JSONResponse(content={'status': 500, 'msg': msg, 'data': {}})