package db

// 自动标题的开关（两种对象分开控制）。默认关闭：它会多花一次 LLM 调用，
// 由操作员在「系统 → 设置」里显式打开。
const (
	SettingTaskAutoTitle = "task_auto_title_enabled"
	SettingChatAutoTitle = "chat_auto_title_enabled"
)
