// Package web provides a web GUI for dnstm.
package web

import (
	"fmt"
	"strings"
	"sync"

	"github.com/net2share/dnstm/internal/actions"
)

// BufferedOutput implements actions.OutputWriter by buffering all output as plain text lines.
// It is used by web API handlers to capture handler output for JSON responses.
type BufferedOutput struct {
	mu    sync.Mutex
	lines []string
}

// NewBufferedOutput creates a new BufferedOutput.
func NewBufferedOutput() *BufferedOutput {
	return &BufferedOutput{}
}

// Lines returns all captured output lines.
func (b *BufferedOutput) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]string, len(b.lines))
	copy(result, b.lines)
	return result
}

func (b *BufferedOutput) append(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, line)
}

func (b *BufferedOutput) Print(msg string) {
	b.append(msg)
}

func (b *BufferedOutput) Printf(format string, args ...interface{}) {
	b.append(fmt.Sprintf(format, args...))
}

func (b *BufferedOutput) Println(args ...interface{}) {
	if len(args) == 0 {
		b.append("")
	} else {
		parts := make([]string, len(args))
		for i, a := range args {
			parts[i] = fmt.Sprint(a)
		}
		b.append(strings.Join(parts, " "))
	}
}

func (b *BufferedOutput) Info(msg string) {
	b.append(actions.SymbolInfo + " " + msg)
}

func (b *BufferedOutput) Success(msg string) {
	b.append(actions.SymbolSuccess + " " + msg)
}

func (b *BufferedOutput) Warning(msg string) {
	b.append(actions.SymbolWarning + " " + msg)
}

func (b *BufferedOutput) Error(msg string) {
	b.append(actions.SymbolError + " " + msg)
}

func (b *BufferedOutput) Status(msg string) {
	b.append(actions.SymbolSuccess + " " + msg)
}

func (b *BufferedOutput) Step(current, total int, msg string) {
	b.append(fmt.Sprintf("[%d/%d] %s", current, total, msg))
}

func (b *BufferedOutput) Box(title string, lines []string) {
	b.append("=== " + title + " ===")
	for _, line := range lines {
		b.append(line)
	}
	b.append("==================")
}

func (b *BufferedOutput) KV(key, value string) string {
	return fmt.Sprintf("%-20s %s", key+":", value)
}

func (b *BufferedOutput) Table(headers []string, rows [][]string) {
	b.append(strings.Join(headers, "  "))
	for _, row := range rows {
		b.append(strings.Join(row, "  "))
	}
}

func (b *BufferedOutput) Separator(length int) {
	b.append(strings.Repeat("-", length))
}

func (b *BufferedOutput) ShowInfo(cfg actions.InfoConfig) error {
	b.append("=== " + cfg.Title + " ===")
	for _, section := range cfg.Sections {
		if section.Title != "" {
			b.append(section.Title + ":")
		}
		for _, row := range section.Rows {
			if row.Key != "" {
				b.append(fmt.Sprintf("  %-20s %s", row.Key+":", row.Value))
			} else {
				b.append("  " + row.Value)
			}
		}
	}
	return nil
}

func (b *BufferedOutput) BeginProgress(title string) {
	b.append(">>> " + title)
}

func (b *BufferedOutput) EndProgress() {}

func (b *BufferedOutput) DismissProgress() {}

func (b *BufferedOutput) IsProgressActive() bool {
	return false
}
