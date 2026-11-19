package server

import (
	"testing"

	"github.com/Domren/jingwei/db"
)

// TestIntranetHeartbeatProbesOnWire 钉住 P17 的落点：周期心跳只允许走 SSH 通道，
// webshell 会话不进入主动探测列表——否则每分钟都会往壳上打一条自发请求，
// 空闲抓包就不为零。webshell 的存活改由真实命令 piggyback，人工心跳按需触发。
func TestIntranetHeartbeatProbesOnWire(t *testing.T) {
	webshellSess := &db.IntranetSession{Transport: db.IntranetTransportWebshell}
	if intranetHeartbeatProbesOnWire(webshellSess) {
		t.Fatal("webshell 会话不应进入周期心跳的主动探测")
	}
	sshSess := &db.IntranetSession{Transport: db.IntranetTransportSSH}
	if !intranetHeartbeatProbesOnWire(sshSess) {
		t.Fatal("SSH 会话应保留自己的通道心跳（不走 webshell wire）")
	}
	// transport 缺省按 webshell 归一化，同样不得主动探测。
	if intranetHeartbeatProbesOnWire(&db.IntranetSession{}) {
		t.Fatal("默认 transport 归一化为 webshell，不应主动探测")
	}
}
