package tui

import "github.com/charmbracelet/lipgloss"

var (
	DocStyle = lipgloss.NewStyle()

	AppStyle = lipgloss.NewStyle().
		Padding(1, 2)

	TitleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#a855f7"))

	SubtitleStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8b949e"))

	SelectedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#a855f7")).
		Bold(true)

	MenuItemStyle = lipgloss.NewStyle().
		Padding(0, 2).
		Foreground(lipgloss.Color("#c9d1d9"))

	StatusStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#3fb950"))

	ErrorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#f85149"))

	InfoStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#79c0ff"))

	BoxStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1)

	HeaderStyle = lipgloss.NewStyle().
		Background(lipgloss.Color("#161b22")).
		Padding(1, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d"))

	ProgressStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#a855f7"))

	DoneStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#3fb950"))

	FailStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#f85149"))

	DimStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#484f58"))

	PendingStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#484f58"))

	RunningStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#d29922"))

	SuccessDot = lipgloss.NewStyle().
			SetString("●").
			Foreground(lipgloss.Color("#3fb950"))

	RunningDot = lipgloss.NewStyle().
			SetString("●").
			Foreground(lipgloss.Color("#d29922"))

	FailedDot = lipgloss.NewStyle().
			SetString("●").
			Foreground(lipgloss.Color("#f85149"))

	PendingDot = lipgloss.NewStyle().
			SetString("○").
			Foreground(lipgloss.Color("#484f58"))

	ModuleNameStyle = lipgloss.NewStyle().
			Width(16).
			Foreground(lipgloss.Color("#c9d1d9"))

	ModuleStatusStyle = lipgloss.NewStyle().
				Width(30)

	ModuleResultStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#8b949e"))

	TargetStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#f0f6fc")).
			Bold(true)

	KeyStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8b949e"))

	ValStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#c9d1d9"))

	TimerStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#d29922"))
)
