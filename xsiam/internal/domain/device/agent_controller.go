package device

import "context"

// AgentController dispatches remote commands to endpoint agents.
type AgentController struct{ enabled bool }

func NewAgentController(enabled bool) *AgentController { return &AgentController{enabled: enabled} }

func (c *AgentController) TriggerAgentUpgrade(_ context.Context, _, _ string) error { return nil }

func (c *AgentController) TriggerAgentUninstall(_ context.Context, _ string) error { return nil }
