// Package zoraxy_plugin is a small, vendored copy of the plugin lifecycle
// contract described in the Zoraxy plugin documentation
// (https://zoraxy.aroz.org/plugins/). It intentionally only implements what
// this plugin needs (Router plugin, dynamic capture, plugin UI) — no calls
// back into the Zoraxy management API are made, so PermittedAPIEndpoints /
// APIKey handling is not required here.
package zoraxy_plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PluginType mirrors Zoraxy's plugin type enum.
type PluginType int

const (
	PluginType_Router    PluginType = 0
	PluginType_Utilities PluginType = 1
)

// ControlStatusCode is the HTTP status code a plugin uses to tell Zoraxy how
// a captured request was handled.
type ControlStatusCode int

const (
	ControlStatusCode_CAPTURED  ControlStatusCode = 280
	ControlStatusCode_UNHANDLED ControlStatusCode = 284
	ControlStatusCode_ERROR     ControlStatusCode = 580
)

// RuntimeConstantValue is passed to the plugin as part of ConfigureSpec.
type RuntimeConstantValue struct {
	ZoraxyVersion    string `json:"zoraxy_version"`
	ZoraxyUUID       string `json:"zoraxy_uuid"`
	DevelopmentBuild bool   `json:"development_build"`
}

// PermittedAPIEndpoint declares a Zoraxy management-API endpoint the plugin
// needs. This plugin does not call back into Zoraxy, so it declares none.
type PermittedAPIEndpoint struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason"`
}

// IntroSpect is printed as JSON when the plugin binary is started with
// -introspect, and describes the plugin to Zoraxy.
type IntroSpect struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Author        string     `json:"author"`
	AuthorContact string     `json:"author_contact"`
	Description   string     `json:"description"`
	URL           string     `json:"url"`
	Type          PluginType `json:"type"`
	VersionMajor  int        `json:"version_major"`
	VersionMinor  int        `json:"version_minor"`
	VersionPatch  int        `json:"version_patch"`

	DynamicCaptureSniff   string `json:"dynamic_capture_sniff"`
	DynamicCaptureIngress string `json:"dynamic_capture_ingress"`

	UIPath string `json:"ui_path"`

	PermittedAPIEndpoints []PermittedAPIEndpoint `json:"permitted_api_endpoints"`
}

// ConfigureSpec is what Zoraxy passes to the plugin via -configure once it
// starts the plugin process.
type ConfigureSpec struct {
	Port         int                  `json:"port"`
	RuntimeConst RuntimeConstantValue `json:"runtime_const"`
	APIKey       string               `json:"api_key,omitempty"`
	ZoraxyPort   int                  `json:"zoraxy_port,omitempty"`
}

// ServeIntroSpect prints the IntroSpect payload and exits when the plugin is
// started with -introspect. Call this before RecvConfigureSpec.
func ServeIntroSpect(spec *IntroSpect) {
	if len(os.Args) > 1 && os.Args[1] == "-introspect" {
		jsonData, _ := json.MarshalIndent(spec, "", " ")
		fmt.Println(string(jsonData))
		os.Exit(0)
	}
}

// RecvConfigureSpec parses the -configure flag Zoraxy starts the plugin
// with.
func RecvConfigureSpec() (*ConfigureSpec, error) {
	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "-configure=") {
			var cfg ConfigureSpec
			if err := json.Unmarshal([]byte(arg[len("-configure="):]), &cfg); err != nil {
				return nil, err
			}
			return &cfg, nil
		} else if arg == "-configure" {
			if len(os.Args) <= i+1 {
				return nil, fmt.Errorf("no value specified after -configure flag")
			}
			var cfg ConfigureSpec
			if err := json.Unmarshal([]byte(os.Args[i+1]), &cfg); err != nil {
				return nil, err
			}
			return &cfg, nil
		}
	}
	return nil, fmt.Errorf("no -configure flag found")
}

// ServeAndRecvSpec combines ServeIntroSpect and RecvConfigureSpec, which is
// the usual way to bootstrap a Zoraxy plugin's main function.
func ServeAndRecvSpec(spec *IntroSpect) (*ConfigureSpec, error) {
	ServeIntroSpect(spec)
	return RecvConfigureSpec()
}
