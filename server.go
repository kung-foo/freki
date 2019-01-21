package freki

// Server interface type
type Server interface {
	Type() string
	Start(p *Processor) error
	Shutdown() error
	Port() uint
}
