package render

import (
	"github.com/usestrix/strix/tui/internal/i18n"
	"strings"
)

// ---------------------------------------------------------------------------
// Simple tools (think, web_search, load_skill) + generic fallback
// ---------------------------------------------------------------------------

func renderThink(args map[string]any) string {
	thought := StringValue(args["thought"])
	var b strings.Builder
	b.WriteString("🧠 " + Bold(Purple).Render(i18n.T("Thinking")) + "\n  ")
	if thought != "" {
		b.WriteString(Dim().Italic(true).Render(thought))
	} else {
		b.WriteString(Dim().Italic(true).Render(i18n.T("Thinking...")))
	}
	return b.String()
}

func renderWebSearch(args map[string]any) string {
	query := StringValue(args["query"])
	var b strings.Builder
	b.WriteString("🌐 " + Bold(InfoBlue).Render(i18n.T("Searching the web...")))
	if query != "" {
		b.WriteString("\n  " + Dim().Render(query))
	}
	return b.String()
}

func renderLoadSkill(args map[string]any, result any) string {
	var requested string
	if list, ok := args["skills"].([]any); ok {
		var parts []string
		for _, s := range list {
			parts = append(parts, StringValue(s))
		}
		requested = strings.Join(parts, ", ")
	} else {
		requested = StringValue(args["skills"])
	}
	var b strings.Builder
	b.WriteString(Col(Emerald).Render("◇ ") + Dim().Render("loading skill"))
	if requested != "" {
		b.WriteString(" " + Col(Emerald).Render(requested))
	} else if result == nil {
		b.WriteString("\n  " + Dim().Render(i18n.T("Loading...")))
	}
	return b.String()
}
