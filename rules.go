package freki

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/google/gopacket/pcap"

	yaml "gopkg.in/yaml.v2"

	"golang.org/x/net/bpf"
)

type RuleType int

const (
	Rewrite RuleType = iota
	ProxyTCP
	ProxySSH
	LogTCP
	LogHTTP
	Drop
	PassThrough
)

type Config struct {
	Rules []*Rule `yaml:"rules"`
}

type Rule struct {
	Match  string `yaml:"match"`
	Type   string `yaml:"type"`
	Target string `yaml:"target,omitempty"`
	Name   string `yaml:"name,omitempty"`

	isInit    bool
	ruleType  RuleType
	index     int
	matcher   *bpf.VM
	targetURL *url.URL

	host string
	port int
}

func (r *Rule) String() string {
	return fmt.Sprintf("Rule: %s", r.Match)
}

func ReadRulesFromFile(file *os.File) ([]*Rule, error) {
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return ParseRuleSpec(data)
}

func ParseRuleSpec(spec []byte) ([]*Rule, error) {
	config := &Config{}
	err := yaml.Unmarshal(spec, config)

	if err != nil {
		return nil, err
	}

	return config.Rules, err
}

func initRule(idx int, rule *Rule, iface *pcap.Handle) error {
	if rule.isInit {
		return nil
	}

	switch rule.Type {
	case "rewrite":
		rule.ruleType = Rewrite
	case "proxy":
		rule.ruleType = ProxyTCP
	case "proxy_ssh":
		rule.ruleType = ProxySSH
	case "log_tcp":
		rule.ruleType = LogTCP
	case "log_http":
		rule.ruleType = LogHTTP
	case "drop":
		rule.ruleType = Drop
	case "passthrough":
		rule.ruleType = PassThrough
	default:
		return fmt.Errorf("unknown rule type: %s", rule.Type)
	}

	if len(rule.Match) > 0 {
		instuctions, err := iface.CompileBPFFilter(rule.Match)
		if err != nil {
			return err
		}

		rule.matcher = pcapBPFToXNetBPF(instuctions)
	}

	if rule.Target != "" {
		var err error
		if rule.ruleType == ProxyTCP || rule.ruleType == ProxySSH {
			rule.targetURL, err = url.Parse(rule.Target)

			if err != nil {
				return err
			}

			var sport string
			rule.host, sport, err = net.SplitHostPort(rule.targetURL.Host)

			if err != nil {
				return err
			}

			rule.port, err = strconv.Atoi(sport)

			if err != nil {
				return err
			}

			// TODO: handle scheme specific validation/parsing
		}

		if rule.ruleType == Rewrite {
			rule.port, err = strconv.Atoi(rule.Target)

			if err != nil {
				return err
			}
		}
	}

	rule.index = idx
	rule.isInit = true

	return nil
}
