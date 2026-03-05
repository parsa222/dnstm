package cmd

import (
	"github.com/net2share/dnstm/internal/web"
	"github.com/spf13/cobra"
)

func init() {
	var addr string

	webCmd := &cobra.Command{
		Use:   "web",
		Short: "Start the web GUI",
		Long: `Start the web-based management interface for dnstm.

Opens a browser-friendly dashboard for managing tunnels, backends,
and the DNS router. By default, listens on 127.0.0.1:9090 (localhost only).

Example:
  sudo dnstm web
  sudo dnstm web --addr 0.0.0.0:9090`,
		RunE: func(cmd *cobra.Command, args []string) error {
			s := web.New(addr)
			return s.Run()
		},
	}

	webCmd.Flags().StringVar(&addr, "addr", "127.0.0.1:9090", "Address to listen on (e.g. 127.0.0.1:9090)")
	rootCmd.AddCommand(webCmd)
}
