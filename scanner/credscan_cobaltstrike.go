package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
)

// Cobalt Strike Team Server (50050) 探针。
//
// 未在真机验证：Team Server 使用私有、加密的 Java 序列化协议，没有公开标准，本平台也
// 没有 Cobalt Strike 专有环境。这里实现的是可复现的最小形态——4 字节大端长度帧 +
// Java 序列化流 magic (AC ED 00 05) 作为协议识别特征，登录帧里带上凭据，命中判定
// 完全依赖服务端回帧里的明确状态字节（0x00 接受 / 0x01 拒绝）。它验证的是框架与
// 六态判定，绝不宣称「已在真机跑通」；私有协议细节需在有授权环境的真机上补齐。
// hit/deny 双路径由 scanner/credscan_adapters_test.go 的进程内协议桩验证。

type cobaltstrikeCredAdapter struct{}

func (cobaltstrikeCredAdapter) Protocol() string { return "cobaltstrike" }

var csJavaStreamMagic = []byte{0xac, 0xed, 0x00, 0x05}

func csFrame(payload []byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

func csReadFrame(w *credWire) ([]byte, error) {
	head, err := w.readN(4)
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(head))
	if n < 0 || n > credReadMax {
		return nil, fmt.Errorf("Team Server 帧长度异常 %d", n)
	}
	return w.readN(n)
}

func (a cobaltstrikeCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	// 不含用户数据的握手探针：Java 序列化流头 + 一个最小的块数据标记。
	probe := append([]byte{}, csJavaStreamMagic...)
	probe = append(probe, 0x77, 0x01, 0x00)
	if err := w.write(csFrame(probe)); err != nil {
		return false, "", err
	}
	resp, err := csReadFrame(w)
	if err != nil {
		return false, credPreview(w.resp), err
	}
	if len(resp) < 4 || !bytes.Equal(resp[:4], csJavaStreamMagic) {
		return false, credPreview(resp), nil
	}
	return true, "Cobalt Strike Team Server 握手（Java 序列化流 magic）", nil
}

func (a cobaltstrikeCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	payload := append([]byte{}, csJavaStreamMagic...)
	payload = append(payload, []byte("LOGIN\x00"+cred.Username+"\x00"+cred.Password)...)
	if err = w.write(csFrame(payload)); err != nil {
		return res.withErr(err)
	}
	resp, err := csReadFrame(w)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = "Team Server 登录应答: " + credPreview(resp)
	if len(resp) == 0 {
		res.Outcome = CredInconclusive
		res.Reason = "Team Server 回了空帧，既未接受也未拒绝，不能对这组凭据下结论"
		return res, nil
	}
	switch resp[0] {
	case 0x00: // 服务端明确接受
		res.Outcome = CredHit
	case 0x01: // 服务端明确拒绝
		res.Outcome = CredDeny
	case 0x02:
		res.Outcome = CredLocked
		res.Reason = "Team Server 提示账号锁定或访问封禁，已停手"
	default:
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("Team Server 回状态 0x%02x，不是明确的接受/拒绝", resp[0])
	}
	return res, nil
}

func init() { RegisterCredAdapter(cobaltstrikeCredAdapter{}) }
