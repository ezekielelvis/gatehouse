// Package pluginpacks embeds the built-in plugin manifests so the default tool
// set ships inside the single binary. Users add or override tools by pointing
// at an external manifest directory (plan §5/§13).
package pluginpacks

import (
	"embed"

	"github.com/gatehouse/gatehouse/internal/plugins"
)

//go:embed manifests/*.yaml
var manifestFS embed.FS

// Builtin loads and validates every embedded manifest.
func Builtin() ([]plugins.Manifest, error) {
	return plugins.LoadDir(manifestFS, "manifests")
}
