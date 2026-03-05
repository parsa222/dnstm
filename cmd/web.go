package cmd

import (
	"fmt"

	"github.com/net2share/dnstm/internal/web"
	"github.com/spf13/cobra"
)

func init() {
	var addr string
	var setPassword string

	webCmd := &cobra.Command{
		Use:   "web",
		Short: "Start the web GUI",
		Long: `Start the web-based management interface for dnstm.

Opens a browser-friendly dashboard for managing tunnels, backends,
and the DNS router. By default, listens on 127.0.0.1:9090 (localhost only).

A password must be set before the web UI is fully secured. Set one with:
  sudo dnstm web --set-password <password>

Example:
  sudo dnstm web
  sudo dnstm web --addr 0.0.0.0:9090
  sudo dnstm web --set-password mysecretpassword`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If --set-password is provided, save it and exit
			if setPassword != "" {
				if err := web.SaveCredentials(setPassword); err != nil {
					return fmt.Errorf("failed to save web credentials: %w", err)
				}
				fmt.Println("✓ Web UI password saved. Start the web server with: sudo dnstm web")
				return nil
			}

			s := web.New(addr)
			return s.Run()
		},
	}

	webCmd.Flags().StringVar(&addr, "addr", "127.0.0.1:9090", "Address to listen on (e.g. 127.0.0.1:9090)")
	webCmd.Flags().StringVar(&setPassword, "set-password", "", "Set the web UI admin password and exit")
	rootCmd.AddCommand(webCmd)
}
