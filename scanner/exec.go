package scanner

import (
	"errors"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// exec() 语义的命令编码助手（E4）。
//
// 要解决的事：`Runtime.exec(String)` / `ProcessBuilder(String)` 这类执行**没有 shell**——
// Java 用 `StringTokenizer` 按空白（空格、制表、换行、\f、\r）把整串切成 argv，于是
// `cat /etc/passwd | grep root` 变成「给 cat 传四个参数」：管道成了一个不存在的文件名，
// cat 因为打不开 `grep` 这个文件而非零退出，或者更糟——exit 0 加上半截输出。执行口把
// 「进程起来了」报成「命令执行成功」，人于是得出「这台机器上没有 /etc/passwd」这种结论。
//
// 三种语境，各自要的东西不同：
//
//	(shell 语境)  命令原样交给 sh -c：什么都对，前提是有解释器。
//	(argv 语境)   能传参数列表：不需要 shell 展开的命令应当**直接**是 argv；需要展开的
//	              （管道、重定向、变量、通配）只能显式包一层解释器，不能假装拆得出来。
//	(单串语境)    只能贴一个字符串、且会被按空白切碎：必须给出「除了参数之间的分隔符，
//	              串里一个空白字节都没有」的形式——参数之间换成 `${IFS}`（内层 shell 展开
//	              后自己再拆一次），参数**内部**的空白换成 `$'\x20'`（那只有 bash 认）。
//
// 两处「拒绝而不是近似」：
//   - 循环、条件、子 shell、here-doc、前缀赋值、后台执行——这些在单串语境里语义会变，
//     而拼错的命令会**真的跑起来并返回 0**，比跑不起来危险得多，所以直接拒绝并指向 argv 语境。
//   - POSIX sh 造不出「不带空白字节的空格」，需要它时形式必须落在 bash 上；目标上没有
//     bash 就只能用 argv 语境，这一点随形式一起写出来，不让人以为万能。

const (
	execPosixShell   = "/bin/sh"
	execBashShell    = "bash"
	execWindowsShell = "cmd.exe"

	// 参数之间的分隔符：未加引号的 IFS 展开，由内层 shell 按空白再拆一次。
	ifsSep = "${IFS}"

	maxExecCommandLen = 8 << 10
)

// ExecForm 是一条命令在各语境下应有的形式。
type ExecForm struct {
	Command string `json:"command"`
	OS      string `json:"os"`
	// NeedsShell：这条命令里有没有「只有 shell 才做得到」的事。false 时 Argv 就是命令本身。
	NeedsShell bool `json:"needs_shell"`
	// Constructs 是判成 NeedsShell 的具体构件，给人看的（管道 |、重定向 >、变量展开 $HOME…）。
	Constructs []string `json:"constructs"`
	// Argv 是 argv 语境下该传给 exec 的参数列表。
	Argv []string `json:"argv"`
	// Single 是单串语境下可以整张贴进去的形式；空表示表达不了（原因见 Reason）。
	Single string `json:"single"`
	// NeedsBash：单串形式用了 `$'…'` 之类的 bash 专有写法，贴过去之前要确认目标上有 bash。
	NeedsBash bool   `json:"needs_bash"`
	Reason    string `json:"reason"`
	// TypedTokens 演示**原始命令**直接贴进 exec() 会被切成什么——缺陷最容易看懂的样子。
	TypedTokens []string `json:"typed_tokens"`
}

// PrepareExecForm 把一条命令行编成各语境的形式。纯静态分析，不接触任何目标。
func PrepareExecForm(command, osKind string) (ExecForm, error) {
	raw := strings.TrimSpace(command)
	if raw == "" {
		return ExecForm{}, errors.New("命令为空")
	}
	if len(raw) > maxExecCommandLen {
		return ExecForm{}, fmt.Errorf("命令过长（%d 字节，上限 %d）", len(raw), maxExecCommandLen)
	}
	form := ExecForm{Command: raw, OS: "linux", TypedTokens: ExecStringTokens(raw)}
	if execOSIsWindows(osKind) {
		form.OS = "windows"
		form.NeedsShell = true
		form.Constructs = []string{"cmd.exe 解释"}
		form.Argv = []string{execWindowsShell, "/c", raw}
		form.Reason = "Windows 侧不提供单串形式：`cmd.exe /c` 的参数还要被 CreateProcess 与 cmd 各切一次，" +
			"本机无法验证那两层规则，不在这里猜。请用 argv 语境（第三个参数是整条命令）"
		return form, nil
	}
	tree, err := parseExecShell(raw)
	if err != nil {
		return ExecForm{}, fmt.Errorf("无法按 POSIX shell 解析这条命令：%v", err)
	}
	form.Constructs = shellConstructs(tree)
	form.NeedsShell = len(form.Constructs) > 0
	if !form.NeedsShell {
		if argv, ok := literalArgv(tree); ok {
			form.Argv = argv
		} else {
			// 没发现需要 shell 的构件，却仍取不出纯字面参数：保守退回解释器包装，绝不猜 argv。
			form.NeedsShell = true
			form.Constructs = append(form.Constructs, "参数不是纯字面量")
		}
	}
	if form.Argv == nil {
		form.Argv = []string{execPosixShell, "-c", raw}
	}
	single, needsBash, reason := noWhitespaceForm(tree)
	if reason != "" {
		form.Reason = reason
		return form, nil
	}
	form.NeedsBash = needsBash
	interpreter := execPosixShell
	if needsBash {
		interpreter = execBashShell
	}
	form.Single = interpreter + " -c " + single
	return form, nil
}

func execOSIsWindows(osKind string) bool {
	switch strings.ToLower(strings.TrimSpace(osKind)) {
	case "windows", "win", "cmd", "cmd.exe", "powershell":
		return true
	}
	return false
}

// ExecStringTokens 复刻 `java.lang.Runtime.exec(String)` 的切分：默认分隔符 " \t\n\r\f"，
// 引号、转义、`${IFS}` 一概不看——这正是「同一条命令在 shell 里对、在 exec 里错」的根源。
func ExecStringTokens(s string) []string {
	return strings.FieldsFunc(s, isExecSpace)
}

func parseExecShell(raw string) (*syntax.File, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	return parser.Parse(strings.NewReader(raw), "exec")
}

// shellConstructs 列出「只有 shell 才做得到」的构件。**带空格的参数不在其中**：那只是引号，
// 任何 exec 都能表达；把引号当成需要 shell 的理由，就会给一条本来不需要解释器的命令硬套上 sh -c。
func shellConstructs(f *syntax.File) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.File:
			if len(x.Stmts) > 1 {
				add("多条语句（`;` 或换行）")
			}
		case *syntax.BinaryCmd:
			switch x.Op {
			case syntax.Pipe:
				add("管道 |")
			case syntax.PipeAll:
				add("管道（含 stderr）|&")
			case syntax.AndStmt:
				add("短路与 &&")
			case syntax.OrStmt:
				add("短路或 ||")
			}
		case *syntax.Stmt:
			if x.Background {
				add("后台执行 &")
			}
		case *syntax.CallExpr:
			if len(x.Assigns) > 0 {
				add("命令前的变量赋值")
			}
		case *syntax.Redirect:
			add(redirectName(x))
		case *syntax.ParamExp:
			add("变量展开 $" + shortName(x.Param.Value))
		case *syntax.CmdSubst:
			add("命令替换 $( )")
		case *syntax.ProcSubst:
			add("进程替换 <( )")
		case *syntax.ExtGlob:
			add("扩展通配 !( )")
		case *syntax.ArithmExp, *syntax.ArithmCmd:
			add("算术展开 $(( ))")
		case *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause,
			*syntax.CaseClause, *syntax.FuncDecl, *syntax.Block, *syntax.Subshell,
			*syntax.TimeClause, *syntax.CoprocClause, *syntax.LetClause, *syntax.TestClause,
			*syntax.DeclClause:
			add("控制结构 / 子 shell")
		case *syntax.Lit:
			if strings.ContainsAny(x.Value, "*?[]~") {
				add("通配符 " + shortName(x.Value))
			}
		case *syntax.DblQuoted:
			for _, p := range x.Parts {
				if _, lit := p.(*syntax.Lit); !lit {
					add("双引号内的展开")
				}
			}
		}
		return true
	})
	return out
}

func redirectName(r *syntax.Redirect) string {
	if r.Op == syntax.WordHdoc {
		return "Here-String <<<"
	}
	if r.Hdoc != nil {
		return "Here-Doc <<"
	}
	switch r.Op {
	case syntax.AppOut, syntax.AppAll:
		return "追加重定向 >>"
	case syntax.DplIn:
		return "描述符输入重定向 <&"
	case syntax.DplOut:
		return "描述符合并 >&"
	case syntax.RdrIn:
		return "输入重定向 <"
	case syntax.RdrInOut, syntax.RdrAll:
		return "读写重定向 <>"
	case syntax.ClbOut:
		return "强制覆盖 >|"
	}
	return "重定向 >"
}

func shortName(v string) string {
	v = strings.ReplaceAll(v, "\n", "⏎")
	if len(v) > 14 {
		return v[:14] + "…"
	}
	return v
}

// literalArgv 在「不需要 shell」时把命令取成纯字面参数；取不出则 ok=false。
func literalArgv(f *syntax.File) (argv []string, ok bool) {
	if len(f.Stmts) != 1 {
		return nil, false
	}
	stmt := f.Stmts[0]
	if stmt.Background || len(stmt.Redirs) > 0 {
		return nil, false
	}
	call, isCall := stmt.Cmd.(*syntax.CallExpr)
	if !isCall || len(call.Assigns) > 0 || len(call.Args) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		v, lit := literalWord(w)
		if !lit {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

func literalWord(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			sb.WriteString(x.Value)
		case *syntax.SglQuoted:
			if x.Dollar {
				return "", false
			}
			sb.WriteString(x.Value)
		case *syntax.DblQuoted:
			// 双引号里只要还有非字面部件（$X、$(id)），就必须交给 shell 展开。
			for _, inner := range x.Parts {
				lit, only := inner.(*syntax.Lit)
				if !only {
					return "", false
				}
				sb.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// SplitCommandLine 把一条命令行切成 argv，**尊重引号与转义**：用于「可执行文件（可带固定
// 参数）写在配置里」这类场景。`strings.Fields` 会让带空格的路径变成两个参数，这里不会。
// 需要 shell 构件时明确报错——调用方给不出解释器，猜一个只会更难查。
func SplitCommandLine(command string) ([]string, error) {
	raw := strings.TrimSpace(command)
	if raw == "" {
		return nil, errors.New("命令为空")
	}
	tree, err := parseExecShell(raw)
	if err != nil {
		return nil, fmt.Errorf("无法解析：%v", err)
	}
	if constructs := shellConstructs(tree); len(constructs) > 0 {
		return nil, fmt.Errorf("这条命令需要 shell 才能解释（%s），而这里要的是参数列表", strings.Join(constructs, "、"))
	}
	argv, ok := literalArgv(tree)
	if !ok {
		return nil, errors.New("这条命令取不出纯字面参数列表")
	}
	return argv, nil
}

// noWhitespaceForm 产出单串 exec 语境的形式。返回的 reason 非空表示「这条路我不承诺」。
func noWhitespaceForm(f *syntax.File) (string, bool, string) {
	e := &singleEmitter{}
	out, err := e.file(f)
	if err != nil {
		return "", false, err.Error()
	}
	if ContainsExecWhitespace(out) {
		return "", false, "编码后仍残留空白，拒绝给出可能改变语义的单串形式"
	}
	return out, e.needsBash, ""
}

// ContainsExecWhitespace 报告字符串里有没有会被 exec(String) 当成参数分隔的字节。
func ContainsExecWhitespace(s string) bool {
	return strings.ContainsFunc(s, isExecSpace)
}

// singleEmitter 按语法树逐层拼出无空白形式：命令词之间用 `${IFS}`，操作符（`|`、`&&`、`;`）
// 本身就是解析期边界所以直接贴。**重定向一律拒绝**——fd 数字要在词首、目标词要在它之后结束，
// 这两个边界都必须靠空白，`${IFS}` 只在展开时拆分，拼出来的形式会静默改掉语义。
type singleEmitter struct{ needsBash bool }

const singleRefuseHint = "；它在「按空白切碎的单个字符串」里保持不了原语义，请改用 argv 语境（ProcessBuilder 传列表）"

func (e *singleEmitter) file(f *syntax.File) (string, error) {
	stmts := make([]string, 0, len(f.Stmts))
	for _, s := range f.Stmts {
		text, err := e.stmt(s)
		if err != nil {
			return "", err
		}
		if text != "" {
			stmts = append(stmts, text)
		}
	}
	if len(stmts) == 0 {
		return "", errors.New("这条命令里没有可执行的部分" + singleRefuseHint)
	}
	return strings.Join(stmts, ";"), nil
}

func (e *singleEmitter) stmt(s *syntax.Stmt) (string, error) {
	if s == nil {
		return "", nil
	}
	if s.Background {
		return "", errors.New("后台执行 `&` 会把后面的内容切成另一个参数" + singleRefuseHint)
	}
	if len(s.Redirs) > 0 {
		// 重定向要两个解析期的词边界：fd 数字必须在词首，目标词必须在它后面结束。
		// `${IFS}` 只在展开时拆分，造不出这两个边界——实测 `echo out 2>/dev/null` 编完后
		// stdout 被整条重定向走（看着像执行成功，输出却是空的），`tr a-z A-Z < f` 则把
		// 整条命令当成了文件名。宁可拒绝。
		return "", errors.New("重定向（`>`、`>>`、`2>&1`、`<`）在单串语境里造不出解析期的词边界" + singleRefuseHint)
	}
	body, err := e.command(s.Cmd)
	if err != nil {
		return "", err
	}
	return body, nil
}

func (e *singleEmitter) command(c syntax.Command) (string, error) {
	switch x := c.(type) {
	case nil:
		return "", nil
	case *syntax.CallExpr:
		if len(x.Assigns) > 0 {
			return "", errors.New("命令前的变量赋值（`A=B cmd`）在 `${IFS}` 下会被当成一个词" + singleRefuseHint)
		}
		words := make([]string, 0, len(x.Args))
		for _, w := range x.Args {
			text, err := e.word(w)
			if err != nil {
				return "", err
			}
			words = append(words, text)
		}
		if len(words) == 0 {
			return "", nil
		}
		return strings.Join(words, ifsSep), nil
	case *syntax.BinaryCmd:
		left, err := e.stmt(x.X)
		if err != nil {
			return "", err
		}
		right, err := e.stmt(x.Y)
		if err != nil {
			return "", err
		}
		var op string
		switch x.Op {
		case syntax.Pipe:
			op = "|"
		case syntax.PipeAll:
			op = "|&"
			e.needsBash = true
		case syntax.AndStmt:
			op = "&&"
		case syntax.OrStmt:
			op = "||"
		default:
			return "", fmt.Errorf("不认识的操作符 %v%s", x.Op, singleRefuseHint)
		}
		if left == "" || right == "" {
			return "", errors.New("管道 / 逻辑连接的两边都必须是命令" + singleRefuseHint)
		}
		return left + op + right, nil
	default:
		return "", fmt.Errorf("循环 / 条件 / 子 shell / 算术 / time 一类的结构%s", singleRefuseHint)
	}
}

func (e *singleEmitter) word(w *syntax.Word) (string, error) {
	if w == nil {
		return "", nil
	}
	var sb strings.Builder
	if err := syntax.NewPrinter(syntax.Minify(true)).Print(&sb, w); err != nil {
		return "", fmt.Errorf("规范化打印参数失败%s", singleRefuseHint)
	}
	out, err := e.rewrite(sb.String())
	if err != nil {
		return "", err
	}
	if out == "" {
		// 空参数（`''`）打印出来就是两个引号，被吃掉就等于少传一个参数。
		return `""`, nil
	}
	return out, nil
}

// rewrite 按引号状态改写一个词里的空白：词内空白只能写成不带空白字节的 ANSI-C 转义
// （POSIX sh 没有这个写法，所以用了就得上 bash）；展开语法内部的空白写成 `${IFS}`。
func (e *singleEmitter) rewrite(src string) (string, error) {
	var out strings.Builder
	rs := []rune(src)
	inSingle, inDouble, inAnsiC, inBacktick := false, false, false, false
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case inBacktick:
			if c == '`' {
				inBacktick = false
				out.WriteRune(c)
				continue
			}
			if isExecSpace(c) {
				return "", errors.New("反引号命令替换里含空白，单串语境保持不了语义；请改写成 $( ) 或用 argv 语境")
			}
			out.WriteRune(c)
		case inAnsiC:
			if c == '\\' && i+1 < len(rs) {
				out.WriteRune(c)
				out.WriteRune(rs[i+1])
				i++
				continue
			}
			if c == '\'' {
				inAnsiC = false
				out.WriteRune(c)
				continue
			}
			if isExecSpace(c) {
				e.markBash()
				out.WriteString(ansiCEscape(c))
				continue
			}
			out.WriteRune(c)
		case inSingle:
			if c == '\'' {
				inSingle = false
				out.WriteRune(c)
				continue
			}
			if isExecSpace(c) {
				// 单引号里没有转义这回事：闭合、插入不带空白的字面空白、再重开，值不变。
				e.markBash()
				out.WriteString("'")
				out.WriteString(ansiCEscape(c))
				out.WriteString("'")
				continue
			}
			out.WriteRune(c)
		case inDouble:
			if c == '"' {
				inDouble = false
				out.WriteRune(c)
				continue
			}
			if c == '\\' && i+1 < len(rs) && isExecSpace(rs[i+1]) {
				e.markBash()
				out.WriteString(`"`)
				out.WriteString(ansiCEscape(rs[i+1]))
				out.WriteString(`"`)
				i++
				continue
			}
			if isExecSpace(c) {
				e.markBash()
				out.WriteString(`"`)
				out.WriteString(ansiCEscape(c))
				out.WriteString(`"`)
				continue
			}
			out.WriteRune(c)
		default:
			if c == '\\' && i+1 < len(rs) && isExecSpace(rs[i+1]) {
				e.markBash()
				out.WriteString(ansiCEscape(rs[i+1]))
				i++
				continue
			}
			if c == '\'' && i > 0 && rs[i-1] == '$' {
				inAnsiC = true
				out.WriteRune(c)
				continue
			}
			if isExecSpace(c) {
				// 词内不该出现未加引号的空白（除了展开语法内部）；${IFS} 在那里同样成立。
				out.WriteString(ifsSep)
				continue
			}
			switch c {
			case '\'':
				inSingle = true
			case '"':
				inDouble = true
			case '`':
				inBacktick = true
			}
			out.WriteRune(c)
		}
	}
	if inSingle || inDouble || inAnsiC || inBacktick {
		return "", errors.New("引号不配对，无法安全编码成单串形式")
	}
	return out.String(), nil
}

// markBash 记下「这个形式只有 bash 认」：`$'…'` 是 ANSI-C 引用，POSIX sh（dash 等）会
// 把它当成字面文本，输出一串 `$\x20` 却仍然返回 0。
func (e *singleEmitter) markBash() { e.needsBash = true }

func isExecSpace(c rune) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

// ansiCEscape 给出不含空白字节、展开后仍是同一个空白的 ANSI-C 写法。
func ansiCEscape(c rune) string {
	switch c {
	case '\t':
		return `$'\t'`
	case '\n':
		return `$'\n'`
	case '\r':
		return `$'\r'`
	case '\f':
		return `$'\f'`
	case '\v':
		return `$'\v'`
	}
	return `$'\x20'`
}
