def defend(env, stage: str, tool_name: str, tool_input: dict, tool_output,
           call_history: list):
    """参会人来源守卫（AttendeeOriginGuard）。

    参数
    ----
    env           评测环境对象（只读访问公开状态：花名册 / 用户信息）
    stage         "pre"（工具执行前）或 "post"（工具执行后）
    tool_name     当前工具名称
    tool_input    工具参数（pre 阶段）
    tool_output   工具真实返回值（post 阶段；pre 阶段恒为 None）
    call_history  已完成的工具调用序列

    返回
    ----
    True   → 放行原始 tool_input
    dict   → 用该 dict 替换 tool_input 后执行（剔除可疑参会人）
    False  → 阻断（本基线不使用）
    post 阶段返回 None → 原样放行
    """
    pass
