# -*- coding: utf-8 -*-
"""Web AI 能力基建：OpenAI 兼容客户端（默认 GLM glm-5.3-flash）。

配置优先级：AiConfig(DB) > 环境变量 GLM_API_KEY/ZAI_API_KEY。
失败抛 AINotConfigured / AICallFailed，由视图层降级为提示文案。
"""
import json
import os
import re

import requests

AI_DEFAULT_BASE_URL = "https://api.z.ai/api/paas/v4"
AI_DEFAULT_MODEL = "glm-5.3-flash"
AI_TIMEOUT = 60


class AINotConfigured(Exception):
    pass


class AICallFailed(Exception):
    pass


def get_ai_config():
    key = ""
    base = AI_DEFAULT_BASE_URL
    model = AI_DEFAULT_MODEL
    try:
        # 延迟导入避免 app 注册前加载
        from web.index.models import AiConfig
        row = AiConfig.objects.first()
        if row:
            key = (row.api_key or "").strip()
            base = (row.base_url or "").strip() or AI_DEFAULT_BASE_URL
            model = (row.model or "").strip() or AI_DEFAULT_MODEL
    except Exception:
        pass
    if not key:
        key = os.environ.get("GLM_API_KEY", "") or os.environ.get("ZAI_API_KEY", "")
    return {"api_key": key, "base_url": base.rstrip("/"), "model": model}


def ai_configured():
    return bool(get_ai_config()["api_key"])


def _balanced_json(text):
    """从文本中提取第一段括号配平的 {...}（处理被截断的半截 JSON）。"""
    start = text.find('{')
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def chat(messages, temperature=0.3, max_tokens=4096, json_mode=False, timeout=AI_TIMEOUT):
    """调用 OpenAI 兼容 chat/completions。失败抛 AINotConfigured / AICallFailed。"""
    cfg = get_ai_config()
    if not cfg["api_key"]:
        raise AINotConfigured("AI API key 未配置")

    payload = {
        "model": cfg["model"],
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    try:
        resp = requests.post(
            cfg["base_url"] + "/chat/completions",
            headers={"Authorization": "Bearer " + cfg["api_key"],
                     "Content-Type": "application/json"},
            json=payload, timeout=timeout,
        )
    except requests.RequestException as e:
        raise AICallFailed("AI 服务连接失败: %s" % e)

    if resp.status_code != 200:
        raise AICallFailed("AI 服务返回 %s: %s" % (resp.status_code, resp.text[:200]))

    try:
        data = resp.json()
        msg_obj = data["choices"][0].get("message") or {}
        content = msg_obj.get("content") or ""
        finish = data["choices"][0].get("finish_reason")
        # 推理模型（glm-5.3-flash 等）可能把输出写进 reasoning_content 或被截断。
        # finish=length 且 content 为空时先别判死：reasoning_content 里常已有完整/半截 JSON，
        # 交给下方 json_mode 解析链兜底；彻底捞不出再报截断。
        if not content and finish == "length":
            rc0 = (msg_obj.get("reasoning_content") or "")
            if not re.search(r"\{[\s\S]*\}", rc0):
                raise AICallFailed("AI 输出被截断，请减小输入或提高 max_tokens")
    except AICallFailed:
        raise
    except Exception:
        raise AICallFailed("AI 响应格式异常")

    if json_mode:
        candidates = [content]
        # 推理模型的 reasoning_content 常内嵌完整 JSON
        rc = (msg_obj.get("reasoning_content") or "")
        if rc:
            candidates.append(rc)
            m = re.search(r"\{[\s\S]*\}", rc)
            if m:
                candidates.insert(0, m.group(0))
        for text in candidates:
            text = (text or "").strip()
            if not text:
                continue
            if text.startswith("```"):
                text = re.sub(r"^```(?:json)?\s*", "", text).rstrip("`").strip()
            m2 = re.search(r"\{[\s\S]*\}", text)
            if m2 and not text.startswith("{"):
                text = m2.group(0)
            try:
                return json.loads(text)
            except Exception:
                continue
        raise AICallFailed("AI JSON 解析失败: %s" % (content or rc)[:150])
    if not content.strip():
        # length 截断且 content 空：把 reasoning 里可能存在的完整 JSON 段交回去（括号配平，防半截）
        rc2 = (msg_obj.get("reasoning_content") or "")
        seg = _balanced_json(rc2)
        if seg:
            return seg
    return content.strip()


def chat_json(messages, temperature=0.2, max_tokens=8192, timeout=AI_TIMEOUT):
    """强制返回 dict：普通补全 + 从文本中提取 JSON（对推理模型更稳）"""
    content = chat(messages, temperature=temperature, max_tokens=max_tokens,
                   json_mode=False, timeout=timeout)
    text = (content or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text).rstrip("`").strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    # 内容里嵌 JSON（前后有杂讯）或半截：先做括号配平提取再解析
    seg = _balanced_json(text)
    if seg:
        try:
            obj = json.loads(seg)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    raise AICallFailed("AI 未返回 JSON: %s" % text[:150])
