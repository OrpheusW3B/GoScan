package tui

import (
	"SCANNER/config"
	"SCANNER/scanner"

	tea "github.com/charmbracelet/bubbletea"
)

type statusMsg string

type moduleDoneMsg struct {
	Name   string
	Result interface{}
	Error  error
}

type scanCompleteMsg struct {
	Result *scanner.ScanResult
	Error  error
}

func runScan(cfg *config.Config, moduleCh chan interface{}) tea.Cmd {
	go func() {
		runner := scanner.NewRunner(cfg)
		runner.OnModuleComplete = func(mr scanner.ModuleResult) {
			select {
			case moduleCh <- moduleDoneMsg{Name: mr.Name, Result: mr.Result, Error: mr.Error}:
			default:
			}
		}
		runner.OnStatus = func(msg string) {
			select {
			case moduleCh <- statusMsg(msg):
			default:
			}
		}
		result, err := runner.Run()
		moduleCh <- scanCompleteMsg{Result: result, Error: err}
		close(moduleCh)
	}()

	return waitForModule(moduleCh)
}

func waitForModule(ch chan interface{}) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}
