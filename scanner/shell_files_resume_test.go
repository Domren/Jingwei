package scanner

import (
	"bytes"
	"fmt"
	"testing"
)

// fakeRemoteFile 用内存模拟远端文件，读写都遵守平台分片封顶：写按 256 KiB，
// 读按 ClampShellFileReadLength 收敛。写时用 start 截断、按 offset 落盘，
// 与 WriteShellFile 的协议语义一致。
type fakeRemoteFile struct {
	buf []byte
}

func (f *fakeRemoteFile) writeChunk(offset int64, start bool, data []byte) error {
	if err := ValidateShellFileWriteChunk(len(data)); err != nil {
		return err
	}
	if offset < 0 || (start && offset != 0) {
		return fmt.Errorf("非法偏移量 %d (start=%v)", offset, start)
	}
	end := int(offset) + len(data)
	if start || end > len(f.buf) {
		grown := make([]byte, end)
		copy(grown, f.buf)
		f.buf = grown
	}
	copy(f.buf[offset:end], data)
	return nil
}

func (f *fakeRemoteFile) readChunk(offset int64, length int) ([]byte, bool) {
	length = ClampShellFileReadLength(length)
	if offset < 0 || offset >= int64(len(f.buf)) {
		return nil, true
	}
	end := int(offset) + length
	if end > len(f.buf) {
		end = len(f.buf)
	}
	return f.buf[offset:end], end == len(f.buf)
}

// TestShellFile1MiBInterruptedResumeByteIdentical 1 MiB 文件写到第 3 块时中断，
// 记录已落盘字节数作为续传起点，续传剩余块后字节级一致；再按分片读回拼装，
// 读路径同样字节级一致。全程纯内存，不依赖真实 webshell。
func TestShellFile1MiBInterruptedResumeByteIdentical(t *testing.T) {
	const size = 1 << 20 // 1 MiB
	original := make([]byte, size)
	for i := range original {
		original[i] = byte((i*31 + i/251) % 256)
	}

	remote := &fakeRemoteFile{}
	plan := PlanShellFileChunks(size, ShellFileChunkSize, 0)
	if len(plan) != 4 {
		t.Fatalf("1 MiB 按 256 KiB 应切成 4 块，实际 %d 块", len(plan))
	}

	// 前 3 块写入成功，第 4 块投递前中断（模拟连接断开）。
	resumeOffset := int64(0)
	for i, r := range plan {
		if i == len(plan)-1 {
			break
		}
		if err := remote.writeChunk(r.Offset, i == 0, original[r.Offset:r.Offset+int64(r.Length)]); err != nil {
			t.Fatalf("写入第 %d 块失败: %v", i, err)
		}
		resumeOffset = r.Offset + int64(r.Length)
	}
	if resumeOffset != 3*int64(ShellFileChunkSize) {
		t.Fatalf("中断点应为 3 块边界，实际 %d", resumeOffset)
	}

	// 续传：从已落盘偏移继续，不重发之前的块。
	resumePlan := PlanShellFileChunks(size, ShellFileChunkSize, resumeOffset)
	if len(resumePlan) != 1 || resumePlan[0].Offset != resumeOffset {
		t.Fatalf("续传计划应只剩 1 块且起点为 %d，实际 %+v", resumeOffset, resumePlan)
	}
	for _, r := range resumePlan {
		if err := remote.writeChunk(r.Offset, false, original[r.Offset:r.Offset+int64(r.Length)]); err != nil {
			t.Fatalf("续传块写入失败: %v", err)
		}
	}
	if !bytes.Equal(remote.buf, original) {
		t.Fatalf("1 MiB 中断续传后与原文不一致：len=%d", len(remote.buf))
	}

	// 读路径：按最大读长分片读回拼装，验证字节级一致。
	assembled := make([]byte, 0, size)
	for off := int64(0); off < size; {
		data, eof := remote.readChunk(off, 1<<20) // 请求 1 MiB，应被封顶到 512 KiB
		assembled = append(assembled, data...)
		if len(data) == 0 || eof {
			break
		}
		off += int64(len(data))
	}
	if !bytes.Equal(assembled, original) {
		t.Fatalf("分片读回与原文不一致：len=%d", len(assembled))
	}
}

// TestClampShellFileReadLength 读长封顶收敛到单一实现：默认 256 KiB、
// 上限 512 KiB，显式小值原样保留。scanner 与 HTTP 层共用它，避免漂移。
func TestClampShellFileReadLength(t *testing.T) {
	if got := ClampShellFileReadLength(0); got != ShellFileChunkSize {
		t.Fatalf("默认读长=%d，期望 %d", got, ShellFileChunkSize)
	}
	if got := ClampShellFileReadLength(1 << 20); got != ShellFileMaxRead {
		t.Fatalf("1 MiB 读长应封顶到 %d，实际 %d", ShellFileMaxRead, got)
	}
	if got := ClampShellFileReadLength(1234); got != 1234 {
		t.Fatalf("小读长应保留，实际 %d", got)
	}
}

// TestValidateShellFileWriteChunkRejectsOversize 单块写入超过 256 KiB 被拒。
func TestValidateShellFileWriteChunkRejectsOversize(t *testing.T) {
	if err := ValidateShellFileWriteChunk(ShellFileChunkSize); err != nil {
		t.Fatalf("恰好 256 KiB 应放行: %v", err)
	}
	if err := ValidateShellFileWriteChunk(ShellFileChunkSize + 1); err == nil {
		t.Fatal("超过 256 KiB 的写入未被拒绝")
	}
}
