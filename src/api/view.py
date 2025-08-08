import json  # 在顶部导入
import logging
import os
from fastapi import APIRouter, File, UploadFile, Form
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import Field
from typing import Dict, List, Optional

from .schema import AnonymizeModel, AnalyzeModel, AnalyzeResult, OperatorConf, CustomAnalyze, FileAnalyzeModel, Lang
from ..core.presido import pii_engine

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
    return JSONResponse(content={'code': 500, 'message': msg, 'data': []})

  return JSONResponse(content={'code': 200, 'message': 'ok', 'data': entities_list})


@router.get('/supported_anonymizers')
def supported_anonymizers():
  try:
    operators = pii_engine.get_supported_anonymizers()
  except Exception as e:
    msg = f"get_supported_anonymizers error: {e}"
    logger.exception(msg)
    return JSONResponse(content={'code': 500, 'message': msg, 'data': []})

  return JSONResponse(content={'code': 200, 'message': 'ok', 'data': operators})


@router.post('/anonymize')
def anonymize(item: AnonymizeModel):
  try:
    validate_open_key(item.llm_synthesize)
    result = pii_engine.anonymize(item.text, item.analyzer_results, item.llm_synthesize, item.operators)
  except Exception as e:
    msg = f"anonymize error: {e}"
    logger.exception(msg)
    return JSONResponse(content={'code': 500, 'message': msg, 'data': []})

  return JSONResponse(content={'code': 200, 'message': 'ok', 'data': result})


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
    return JSONResponse(content={'code': 500, 'message': msg, 'data': result})

  return JSONResponse(content={'code': 200, 'message': 'ok', 'data': result})


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
    return JSONResponse(content={'code': 500, 'message': msg, 'data': result})

  return JSONResponse(content={'code': 200, 'message': 'ok', 'data': result})


@router.post('/file_analyze')
def file_analyze(item: FileAnalyzeModel):
  """动态实体脱敏处理"""
  result_data = {"analyze": [], "anonymize": ""}

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

    result_data["source"] = item.text
    result_data["analyze"] = result_analyze

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

      result_data["anonymize"] = anonymize_result

  except Exception as e:
    msg = f"文件脱敏处理错误: {e}"
    logger.exception(msg)
    return JSONResponse(content={'code': 500, 'message': msg, 'data': result_data})

  return JSONResponse(content={'code': 200, 'message': 'ok', 'data': result_data})


@router.post('/file_upload_analyze')
async def file_upload_analyze(
  file: UploadFile = File(...),
  lang: str = Form("zh"),  # 使用Form参数
  entity_mapping: str = Form('{"PERSON": "[姓名]"}'),  # 使用Form参数
  with_anonymize: bool = Form(False),  # 使用Form参数
  llm_synthesize: bool = Form(False)  # 使用Form参数
):
  """文件上传脱敏处理"""
  try:
    # 验证文件类型
    if not file.filename or not file.filename.endswith('.txt'):
      return JSONResponse(
        content={
          'status': 400,
          'msg': '只支持文本文件(.txt)',
          'data': {}
        }
      )

    # 读取文件内容 - 确保正确处理编码
    content_bytes = await file.read()
    try:
      # 尝试UTF-8解码
      content = content_bytes.decode('utf-8')
    except UnicodeDecodeError:
      # 尝试其他常见编码
      for encoding in ['gbk', 'gb2312', 'latin-1']:
        try:
          content = content_bytes.decode(encoding)
          break
        except UnicodeDecodeError:
          continue
      else:
        # 所有编码尝试都失败
        return JSONResponse(
          content={
            'status': 400,
            'msg': '无法解码文件内容',
            'data': {}
          }
        )

    # 解析JSON配置
    try:
      mapping = json.loads(entity_mapping)
    except json.JSONDecodeError as e:
      return JSONResponse(
        content={
          'status': 400,
          'msg': f'JSON格式错误: {str(e)}',
          'data': {}
        }
      )

    # 构建请求模型
    request_data = FileAnalyzeModel(
      text=content,
      lang=Lang(lang),  # 将字符串转换为枚举
      entity_mapping=mapping,
      with_anonymize=with_anonymize,
      llm_synthesize=llm_synthesize
    )

    # 调用处理函数
    return file_analyze(request_data)

  except Exception as e:
    msg = f"文件上传处理错误: {e}"
    logger.exception(msg)
    return JSONResponse(content={'status': 500, 'msg': msg, 'data': {}})