"""全局模板注入：AI 配置状态（供 base.html 顶部提示条）。"""


def ai_status(request):
    """ai_ready / ai_not_ready 注入所有 dashboard 模板。"""
    try:
        from web.utils_ai import ai_configured
        ready = ai_configured()
    except Exception:
        ready = False
    return {"ai_ready": ready, "ai_not_ready": not ready}
